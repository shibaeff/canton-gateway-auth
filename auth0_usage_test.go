package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNormalizeAuth0BaseURL(t *testing.T) {
	for input, want := range map[string]string{
		"tenant.eu.auth0.com":          "https://tenant.eu.auth0.com",
		"https://tenant.eu.auth0.com/": "https://tenant.eu.auth0.com",
	} {
		got, err := normalizeAuth0BaseURL(input)
		if err != nil || got != want {
			t.Fatalf("normalizeAuth0BaseURL(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "http://tenant.eu.auth0.com", "ftp://tenant.eu.auth0.com", "https://tenant.eu.auth0.com/path"} {
		if _, err := normalizeAuth0BaseURL(input); err == nil {
			t.Fatalf("normalizeAuth0BaseURL(%q) unexpectedly succeeded", input)
		}
	}
}

func TestCheckpointFromLink(t *testing.T) {
	header := `<https://tenant.eu.auth0.com/api/v2/logs?from=next-checkpoint&take=100>; rel="next"`
	if got := checkpointFromLink(header); got != "next-checkpoint" {
		t.Fatalf("checkpointFromLink() = %q", got)
	}
}

func TestNormalizeAuth0ClientLabel(t *testing.T) {
	for input, want := range map[string]string{
		"Canton Indexer (dev1)": "canton-indexer-dev1",
		"  M2M / Reader  ":      "m2m-reader",
		"---":                   "client",
	} {
		if got := normalizeAuth0ClientLabel(input); got != want {
			t.Fatalf("normalizeAuth0ClientLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAuth0UsageCollectorBootstrapsAndPersistsMetrics(t *testing.T) {
	var logRequests int
	var clientRequests int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" && r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s", r.Method)
				http.Error(w, "wrong method", http.StatusMethodNotAllowed)
				return
			}
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode token request: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if request["audience"] != server.URL+"/api/v2/" || request["grant_type"] != "client_credentials" {
				t.Errorf("unexpected token request: %#v", request)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 3600})
		case "/api/v2/logs":
			logRequests++
			if r.URL.Query().Get("per_page") == "1" {
				json.NewEncoder(w).Encode([]auth0LogEntry{{LogID: "start"}})
				return
			}
			switch r.URL.Query().Get("from") {
			case "start":
				next := server.URL + "/api/v2/logs?from=next-checkpoint&take=100"
				w.Header().Set("Link", "<"+next+">; rel=\"next\"")
				json.NewEncoder(w).Encode([]auth0LogEntry{
					{LogID: "log-1", Type: auth0SuccessClientCredentials, ClientID: "known-id"},
					{LogID: "log-2", Type: auth0FailedClientCredentials, ClientID: "unknown-id"},
					{LogID: "log-3", Type: "s", ClientID: "known-id"},
					{LogID: "log-4", Type: auth0SuccessClientCredentials, ClientID: "indexer-id"},
				})
			case "next-checkpoint":
				json.NewEncoder(w).Encode([]auth0LogEntry{})
			default:
				t.Errorf("unexpected checkpoint: %q", r.URL.Query().Get("from"))
				http.Error(w, "bad checkpoint", http.StatusBadRequest)
			}
		case "/api/v2/clients":
			clientRequests++
			if r.URL.Query().Get("app_type") != "non_interactive" || r.URL.Query().Get("include_totals") != "true" {
				t.Errorf("unexpected client inventory query: %s", r.URL.RawQuery)
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(auth0ClientsPage{
				Clients: []auth0Client{
					{ClientID: "known-id", Name: "Ignored static name", AppType: "non_interactive"},
					{ClientID: "indexer-id", Name: "Canton Indexer (dev1)", AppType: "non_interactive", ClientMetadata: map[string]string{"workload": "canton-indexer"}},
					{ClientID: "idle-id", Name: "Idle M2M", AppType: "non_interactive"},
				},
				Total: 3, Start: 0, Limit: 100,
			})
		case "/api/v2/stats/daily":
			if r.URL.Query().Get("from") == "" || r.URL.Query().Get("to") == "" {
				t.Error("daily stats date range is missing")
				http.Error(w, "missing date range", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode([]map[string]any{{
				"date": "2026-08-26T00:00:00Z", "logins": 11, "signups": 2, "leaked_passwords": 1,
			}})
		case "/api/v2/stats/active-users":
			json.NewEncoder(w).Encode(17)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := auth0UsageConfig{
		Environment: "dev1", Node: "validator-dev1", BaseURL: server.URL,
		ClientID: "reader", ClientSecret: "secret", ClientNames: map[string]string{"known-id": "openzeppelin"},
		StateFile: filepath.Join(t.TempDir(), "state.json"), PollInterval: time.Minute, DailyLookback: 31, MaxLogPages: 10,
	}
	registry := prometheus.NewRegistry()
	collector, err := newAuth0UsageCollector(cfg, server.Client(), registry)
	if err != nil {
		t.Fatal(err)
	}

	collector.collect(context.Background()) // Establishes a forward-only checkpoint without backfilling.
	if collector.state.Checkpoint != "start" {
		t.Fatalf("bootstrap checkpoint = %q", collector.state.Checkpoint)
	}
	collector.collect(context.Background())
	if collector.state.Checkpoint != "next-checkpoint" {
		t.Fatalf("advanced checkpoint = %q", collector.state.Checkpoint)
	}
	if got := testutil.ToFloat64(collector.metrics.m2m.WithLabelValues("dev1", "validator-dev1", "openzeppelin", "success")); got != 1 {
		t.Fatalf("known success exchanges = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.m2m.WithLabelValues("dev1", "validator-dev1", "other", "failure")); got != 1 {
		t.Fatalf("other failed exchanges = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.m2mClients.WithLabelValues("dev1", "validator-dev1", "openzeppelin")); got != 1 {
		t.Fatalf("configured client inventory = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.m2mClients.WithLabelValues("dev1", "validator-dev1", "canton-indexer")); got != 1 {
		t.Fatalf("discovered client inventory = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.m2m.WithLabelValues("dev1", "validator-dev1", "canton-indexer", "success")); got != 1 {
		t.Fatalf("discovered client exchanges = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.m2mClients.WithLabelValues("dev1", "validator-dev1", "idle-m2m")); got != 1 {
		t.Fatalf("idle client inventory = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.m2m.WithLabelValues("dev1", "validator-dev1", "idle-m2m", "success")); got != 0 {
		t.Fatalf("idle client exchanges = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.daily.WithLabelValues("dev1", "validator-dev1", "2026-08-26", "logins")); got != 11 {
		t.Fatalf("daily logins = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.activeUsers.WithLabelValues("dev1", "validator-dev1")); got != 17 {
		t.Fatalf("active users = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.collectorUp.WithLabelValues("dev1", "validator-dev1")); got != 1 {
		t.Fatalf("collector up = %v", got)
	}
	if logRequests != 2 {
		t.Fatalf("log requests = %d, want 2", logRequests)
	}
	if clientRequests != 2 {
		t.Fatalf("client inventory requests = %d, want 2", clientRequests)
	}

	restarted, err := newAuth0UsageCollector(cfg, server.Client(), prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(restarted.metrics.m2m.WithLabelValues("dev1", "validator-dev1", "openzeppelin", "success")); got != 1 {
		t.Fatalf("persisted success exchanges = %v", got)
	}
}

func TestAuth0UsageCollectorReportsAPIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()
	cfg := auth0UsageConfig{
		Environment: "dev1", Node: "validator-dev1", BaseURL: server.URL,
		ClientID: "reader", ClientSecret: "secret", ClientNames: map[string]string{},
		StateFile: filepath.Join(t.TempDir(), "state.json"), PollInterval: time.Minute, DailyLookback: 31, MaxLogPages: 10,
	}
	collector, err := newAuth0UsageCollector(cfg, server.Client(), prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	collector.collect(context.Background())
	if got := testutil.ToFloat64(collector.metrics.errors.WithLabelValues("token")); got != 1 {
		t.Fatalf("token errors = %v", got)
	}
	if got := testutil.ToFloat64(collector.metrics.collectorUp.WithLabelValues("dev1", "validator-dev1")); got != 0 {
		t.Fatalf("collector up after failure = %v", got)
	}
}

func TestCheckpointURLIsOpaque(t *testing.T) {
	checkpoint := "Cg1HRUY3NEszUERFME40GgAiAQgCEj+/="
	header := "<https://tenant.eu.auth0.com/api/v2/logs?" + url.Values{"from": {checkpoint}, "take": {"100"}}.Encode() + ">; rel=\"next\""
	if got := checkpointFromLink(header); got != checkpoint {
		t.Fatalf("checkpointFromLink() = %q, want %q", got, checkpoint)
	}
}

func TestClientDiscoveryFailurePreservesAttribution(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		wantRefresh bool
	}{
		{"unauthorized", http.StatusUnauthorized, true},
		{"forbidden", http.StatusForbidden, true},
		{"rate-limited", http.StatusTooManyRequests, false},
		{"server-error", http.StatusInternalServerError, false},
	} {
		for _, checkpoint := range []string{"", "before"} {
			t.Run(tc.name+"/checkpoint="+checkpoint, func(t *testing.T) {
				var recovered atomic.Bool
				var tokenRequests, logRequests atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch r.URL.Path {
					case "/oauth/token":
						tokenRequests.Add(1)
						json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 86400})
					case "/api/v2/clients":
						if !recovered.Load() {
							http.Error(w, "inventory unavailable", tc.status)
							return
						}
						json.NewEncoder(w).Encode(auth0ClientsPage{Clients: []auth0Client{{
							ClientID: "new-dar-client", Name: "DAR proxy", AppType: "non_interactive",
							ClientMetadata: map[string]string{"workload": "dar-upload-proxy"},
						}}, Total: 1})
					case "/api/v2/logs":
						logRequests.Add(1)
						if r.URL.Query().Get("per_page") == "1" {
							json.NewEncoder(w).Encode([]auth0LogEntry{{LogID: "before"}})
						} else if r.URL.Query().Get("from") == "before" {
							json.NewEncoder(w).Encode([]auth0LogEntry{{LogID: "after", Type: auth0SuccessClientCredentials, ClientID: "new-dar-client"}})
						} else {
							json.NewEncoder(w).Encode([]auth0LogEntry{})
						}
					case "/api/v2/stats/daily":
						json.NewEncoder(w).Encode([]auth0DailyStats{})
					case "/api/v2/stats/active-users":
						json.NewEncoder(w).Encode(0)
					default:
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				cfg := auth0UsageConfig{
					Environment: "dev1", Node: "validator-dev1", BaseURL: server.URL,
					ClientID: "reader", ClientSecret: "secret", StateFile: filepath.Join(t.TempDir(), "state.json"),
					PollInterval: time.Minute, DailyLookback: 31, MaxLogPages: 10,
				}
				if checkpoint != "" {
					if err := writeAuth0UsageState(cfg.StateFile, auth0UsageState{Checkpoint: checkpoint,
						M2M: map[string]map[string]uint64{"other": {"success": 7}}}); err != nil {
						t.Fatal(err)
					}
				}
				collector, err := newAuth0UsageCollector(cfg, server.Client(), prometheus.NewRegistry())
				if err != nil {
					t.Fatal(err)
				}
				collector.collect(context.Background())
				if logRequests.Load() != 0 {
					t.Fatal("consumed logs without a successful client inventory")
				}
				state, err := loadAuth0UsageState(cfg.StateFile)
				if err != nil || state.Checkpoint != checkpoint {
					t.Fatalf("checkpoint changed on discovery failure: %+v, %v", state, err)
				}
				if got := testutil.ToFloat64(collector.metrics.collectorUp.WithLabelValues("dev1", "validator-dev1")); got != 0 {
					t.Fatalf("collector health during failure = %v", got)
				}
				recovered.Store(true)
				collector.collect(context.Background())
				if checkpoint == "" {
					collector.collect(context.Background()) // First successful poll only bootstraps.
				}
				collector.collect(context.Background()) // No duplicate count on the next poll.
				wantTokens := int64(1)
				if tc.wantRefresh {
					wantTokens = 2
				}
				if tokenRequests.Load() != wantTokens {
					t.Fatalf("token requests = %d, want %d", tokenRequests.Load(), wantTokens)
				}
				if got := testutil.ToFloat64(collector.metrics.m2m.WithLabelValues("dev1", "validator-dev1", "dar-upload-proxy", "success")); got != 1 {
					t.Fatalf("dedicated client exchanges = %v, want 1", got)
				}
				if got := testutil.ToFloat64(collector.metrics.collectorUp.WithLabelValues("dev1", "validator-dev1")); got != 1 {
					t.Fatalf("collector health after recovery = %v", got)
				}
				state, err = loadAuth0UsageState(cfg.StateFile)
				if err != nil || state.Checkpoint != "after" || state.M2M["dar-upload-proxy"]["success"] != 1 {
					t.Fatalf("unexpected durable state after recovery: %+v, %v", state, err)
				}
				wantOther := uint64(0)
				if checkpoint != "" {
					wantOther = 7
				}
				if state.M2M["other"]["success"] != wantOther {
					t.Fatal("recovery changed existing unattributed counts")
				}
			})
		}
	}
}
