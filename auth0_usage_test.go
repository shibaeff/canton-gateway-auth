package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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

func TestAuth0UsageCollectorBootstrapsAndPersistsMetrics(t *testing.T) {
	var logRequests int
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
				})
			case "next-checkpoint":
				json.NewEncoder(w).Encode([]auth0LogEntry{})
			default:
				t.Errorf("unexpected checkpoint: %q", r.URL.Query().Get("from"))
				http.Error(w, "bad checkpoint", http.StatusBadRequest)
			}
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
