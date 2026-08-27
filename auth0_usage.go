package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	auth0SuccessClientCredentials = "seccft"
	auth0FailedClientCredentials  = "feccft"
)

type auth0UsageConfig struct {
	Environment   string
	Node          string
	HTTPAddress   string
	BaseURL       string
	ClientID      string
	ClientSecret  string
	ClientNames   map[string]string
	StateFile     string
	PollInterval  time.Duration
	DailyLookback int
	MaxLogPages   int
}

func loadAuth0UsageConfig() (auth0UsageConfig, error) {
	pollInterval, err := time.ParseDuration(envOr("AUTH0_USAGE_POLL_INTERVAL", "5m"))
	if err != nil || pollInterval < 30*time.Second {
		return auth0UsageConfig{}, errors.New("AUTH0_USAGE_POLL_INTERVAL must be a duration of at least 30s")
	}
	dailyLookback, err := strconv.Atoi(envOr("AUTH0_USAGE_DAILY_LOOKBACK_DAYS", "31"))
	if err != nil || dailyLookback < 1 || dailyLookback > 31 {
		return auth0UsageConfig{}, errors.New("AUTH0_USAGE_DAILY_LOOKBACK_DAYS must be between 1 and 31")
	}
	maxLogPages, err := strconv.Atoi(envOr("AUTH0_USAGE_MAX_LOG_PAGES", "10"))
	if err != nil || maxLogPages < 1 || maxLogPages > 100 {
		return auth0UsageConfig{}, errors.New("AUTH0_USAGE_MAX_LOG_PAGES must be between 1 and 100")
	}

	baseURL, err := normalizeAuth0BaseURL(os.Getenv("AUTH0_DOMAIN"))
	if err != nil {
		return auth0UsageConfig{}, err
	}
	clientID := strings.TrimSpace(os.Getenv("AUTH0_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("AUTH0_CLIENT_SECRET"))
	if clientID == "" || clientSecret == "" {
		return auth0UsageConfig{}, errors.New("AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET are required")
	}

	clientNames, err := parseMapping([]byte(envOr("AUTH0_USAGE_CLIENTS_JSON", `{}`)), true)
	if err != nil {
		return auth0UsageConfig{}, fmt.Errorf("AUTH0_USAGE_CLIENTS_JSON: %w", err)
	}
	cfg := auth0UsageConfig{
		Environment:   envOr("ENVIRONMENT", "dev1"),
		Node:          envOr("NODE", "validator-dev1"),
		HTTPAddress:   envOr("HTTP_ADDRESS", ":9090"),
		BaseURL:       baseURL,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		ClientNames:   clientNames,
		StateFile:     envOr("AUTH0_USAGE_STATE_FILE", "/data/auth0-usage-state.json"),
		PollInterval:  pollInterval,
		DailyLookback: dailyLookback,
		MaxLogPages:   maxLogPages,
	}
	if !normalizedLabel.MatchString(cfg.Environment) || !normalizedLabel.MatchString(cfg.Node) {
		return auth0UsageConfig{}, errors.New("ENVIRONMENT and NODE must be bounded label values")
	}
	return cfg, nil
}

func normalizeAuth0BaseURL(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", errors.New("AUTH0_DOMAIN is required")
	}
	if !strings.Contains(domain, "://") {
		domain = "https://" + domain
	}
	parsed, err := url.Parse(domain)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("AUTH0_DOMAIN must be an Auth0 tenant hostname or base URL")
	}
	if parsed.Scheme != "https" {
		return "", errors.New("AUTH0_DOMAIN must use https")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("AUTH0_DOMAIN must not include a path")
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

type auth0UsageState struct {
	Checkpoint string                       `json:"checkpoint"`
	M2M        map[string]map[string]uint64 `json:"m2m_token_exchanges"`
}

type auth0UsageMetrics struct {
	m2m             *prometheus.CounterVec
	daily           *prometheus.GaugeVec
	activeUsers     *prometheus.GaugeVec
	collectorUp     *prometheus.GaugeVec
	lastSuccess     *prometheus.GaugeVec
	errors          *prometheus.CounterVec
	logsProcessed   prometheus.Counter
	checkpointReady prometheus.Gauge
}

func newAuth0UsageMetrics(reg prometheus.Registerer) *auth0UsageMetrics {
	m := &auth0UsageMetrics{
		m2m: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth0_m2m_token_exchanges_total",
			Help: "Auth0 client-credentials exchanges consumed from tenant logs.",
		}, []string{"environment", "node", "client", "outcome"}),
		daily: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "auth0_tenant_daily_events",
			Help: "Auth0 tenant daily statistics. These do not include M2M token exchanges.",
		}, []string{"environment", "node", "day", "event"}),
		activeUsers: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "auth0_tenant_active_users",
			Help: "Auth0 users active during the preceding 30 days.",
		}, []string{"environment", "node"}),
		collectorUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "auth0_usage_collector_up",
			Help: "Whether the most recent complete Auth0 usage collection succeeded.",
		}, []string{"environment", "node"}),
		lastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "auth0_usage_last_success_timestamp_seconds",
			Help: "Unix timestamp of the most recent complete Auth0 usage collection.",
		}, []string{"environment", "node"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth0_usage_collection_errors_total",
			Help: "Auth0 usage collection errors by operation.",
		}, []string{"operation"}),
		logsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth0_usage_log_entries_processed_total",
			Help: "Auth0 tenant log entries durably processed by the exporter.",
		}),
		checkpointReady: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth0_usage_log_checkpoint_ready",
			Help: "Whether the exporter has established a durable Auth0 log checkpoint.",
		}),
	}
	reg.MustRegister(m.m2m, m.daily, m.activeUsers, m.collectorUp, m.lastSuccess, m.errors, m.logsProcessed, m.checkpointReady)
	return m
}

type auth0UsageCollector struct {
	cfg        auth0UsageConfig
	httpClient *http.Client
	metrics    *auth0UsageMetrics
	state      auth0UsageState
	tokenMu    sync.Mutex
	token      string
	tokenUntil time.Time
}

func newAuth0UsageCollector(cfg auth0UsageConfig, client *http.Client, reg prometheus.Registerer) (*auth0UsageCollector, error) {
	state, err := loadAuth0UsageState(cfg.StateFile)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	c := &auth0UsageCollector{cfg: cfg, httpClient: client, metrics: newAuth0UsageMetrics(reg), state: state}
	for clientName, outcomes := range state.M2M {
		if clientName != "other" && !normalizedLabel.MatchString(clientName) {
			return nil, fmt.Errorf("state contains invalid client label %q", clientName)
		}
		for outcome, count := range outcomes {
			if outcome != "success" && outcome != "failure" {
				return nil, fmt.Errorf("state contains invalid outcome %q", outcome)
			}
			c.metrics.m2m.WithLabelValues(cfg.Environment, cfg.Node, clientName, outcome).Add(float64(count))
		}
	}
	for _, clientName := range cfg.ClientNames {
		c.metrics.m2m.WithLabelValues(cfg.Environment, cfg.Node, clientName, "success").Add(0)
		c.metrics.m2m.WithLabelValues(cfg.Environment, cfg.Node, clientName, "failure").Add(0)
	}
	if state.Checkpoint != "" {
		c.metrics.checkpointReady.Set(1)
	}
	return c, nil
}

func loadAuth0UsageState(path string) (auth0UsageState, error) {
	state := auth0UsageState{M2M: map[string]map[string]uint64{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("read Auth0 usage state: %w", err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("decode Auth0 usage state: %w", err)
	}
	if state.M2M == nil {
		state.M2M = map[string]map[string]uint64{}
	}
	return state, nil
}

func writeAuth0UsageState(path string, state auth0UsageState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create Auth0 usage state directory: %w", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".auth0-usage-state-*")
	if err != nil {
		return fmt.Errorf("create temporary Auth0 usage state: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace Auth0 usage state: %w", err)
	}
	return nil
}

func (c *auth0UsageCollector) run(ctx context.Context) {
	c.collect(ctx)
	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

func (c *auth0UsageCollector) collect(ctx context.Context) {
	token, err := c.accessToken(ctx)
	if err != nil {
		c.collectionFailed("token", err)
		return
	}
	failed := false
	if err := c.collectLogs(ctx, token); err != nil {
		c.collectionFailed("logs", err)
		failed = true
	}
	if err := c.collectStats(ctx, token); err != nil {
		c.collectionFailed("stats", err)
		failed = true
	}
	if failed {
		return
	}
	c.metrics.collectorUp.WithLabelValues(c.cfg.Environment, c.cfg.Node).Set(1)
	c.metrics.lastSuccess.WithLabelValues(c.cfg.Environment, c.cfg.Node).SetToCurrentTime()
}

func (c *auth0UsageCollector) collectionFailed(operation string, err error) {
	c.metrics.collectorUp.WithLabelValues(c.cfg.Environment, c.cfg.Node).Set(0)
	c.metrics.errors.WithLabelValues(operation).Inc()
	slog.Error("Auth0 usage collection failed", "operation", operation, "error", err)
}

type auth0TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (c *auth0UsageCollector) accessToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenUntil) {
		return c.token, nil
	}
	payload, err := json.Marshal(map[string]string{
		"client_id":     c.cfg.ClientID,
		"client_secret": c.cfg.ClientSecret,
		"audience":      c.cfg.BaseURL + "/api/v2/",
		"grant_type":    "client_credentials",
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/oauth/token", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	var response auth0TokenResponse
	if _, err := c.doJSON(request, &response); err != nil {
		return "", err
	}
	if response.AccessToken == "" || response.ExpiresIn <= 0 {
		return "", errors.New("Auth0 token response is incomplete")
	}
	refreshAfter := time.Duration(response.ExpiresIn) * time.Second
	if refreshAfter > time.Minute {
		refreshAfter -= time.Minute
	}
	c.token = response.AccessToken
	c.tokenUntil = time.Now().Add(refreshAfter)
	return c.token, nil
}

type auth0LogEntry struct {
	LogID    string `json:"log_id"`
	Type     string `json:"type"`
	ClientID string `json:"client_id"`
}

func (c *auth0UsageCollector) collectLogs(ctx context.Context, token string) error {
	if c.state.Checkpoint == "" {
		checkpoint, err := c.latestLogCheckpoint(ctx, token)
		if err != nil {
			return err
		}
		if checkpoint == "" {
			return nil
		}
		state := cloneAuth0UsageState(c.state)
		state.Checkpoint = checkpoint
		if err := writeAuth0UsageState(c.cfg.StateFile, state); err != nil {
			return err
		}
		c.state = state
		c.metrics.checkpointReady.Set(1)
		return nil
	}

	for page := 0; page < c.cfg.MaxLogPages; page++ {
		endpoint, err := url.Parse(c.cfg.BaseURL + "/api/v2/logs")
		if err != nil {
			return err
		}
		query := endpoint.Query()
		query.Set("from", c.state.Checkpoint)
		query.Set("take", "100")
		endpoint.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		var entries []auth0LogEntry
		header, err := c.doJSON(request, &entries)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return nil
		}

		nextCheckpoint := checkpointFromLink(header.Get("Link"))
		if nextCheckpoint == "" {
			nextCheckpoint = entries[len(entries)-1].LogID
		}
		if nextCheckpoint == "" || nextCheckpoint == c.state.Checkpoint {
			return errors.New("Auth0 logs response did not advance the checkpoint")
		}

		state := cloneAuth0UsageState(c.state)
		state.Checkpoint = nextCheckpoint
		deltas := map[string]map[string]uint64{}
		for _, entry := range entries {
			outcome := ""
			switch entry.Type {
			case auth0SuccessClientCredentials:
				outcome = "success"
			case auth0FailedClientCredentials:
				outcome = "failure"
			default:
				continue
			}
			clientName := c.cfg.ClientNames[entry.ClientID]
			if clientName == "" {
				clientName = "other"
			}
			incrementNestedCount(state.M2M, clientName, outcome)
			incrementNestedCount(deltas, clientName, outcome)
		}
		if err := writeAuth0UsageState(c.cfg.StateFile, state); err != nil {
			return err
		}
		c.state = state
		for clientName, outcomes := range deltas {
			for outcome, count := range outcomes {
				c.metrics.m2m.WithLabelValues(c.cfg.Environment, c.cfg.Node, clientName, outcome).Add(float64(count))
			}
		}
		c.metrics.logsProcessed.Add(float64(len(entries)))
		if len(entries) < 100 {
			return nil
		}
	}
	return nil
}

func (c *auth0UsageCollector) latestLogCheckpoint(ctx context.Context, token string) (string, error) {
	endpoint, err := url.Parse(c.cfg.BaseURL + "/api/v2/logs")
	if err != nil {
		return "", err
	}
	query := endpoint.Query()
	query.Set("page", "0")
	query.Set("per_page", "1")
	query.Set("sort", "date:-1")
	query.Set("fields", "log_id")
	query.Set("include_fields", "true")
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	var entries []auth0LogEntry
	if _, err := c.doJSON(request, &entries); err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", nil
	}
	return entries[0].LogID, nil
}

func cloneAuth0UsageState(state auth0UsageState) auth0UsageState {
	clone := auth0UsageState{Checkpoint: state.Checkpoint, M2M: map[string]map[string]uint64{}}
	for clientName, outcomes := range state.M2M {
		clone.M2M[clientName] = map[string]uint64{}
		for outcome, count := range outcomes {
			clone.M2M[clientName][outcome] = count
		}
	}
	return clone
}

func incrementNestedCount(counts map[string]map[string]uint64, clientName, outcome string) {
	if counts[clientName] == nil {
		counts[clientName] = map[string]uint64{}
	}
	counts[clientName][outcome]++
}

func checkpointFromLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end <= start {
			continue
		}
		next, err := url.Parse(part[start+1 : end])
		if err == nil {
			return next.Query().Get("from")
		}
	}
	return ""
}

type auth0DailyStats struct {
	Date            time.Time `json:"date"`
	Logins          int64     `json:"logins"`
	Signups         int64     `json:"signups"`
	LeakedPasswords int64     `json:"leaked_passwords"`
}

func (c *auth0UsageCollector) collectStats(ctx context.Context, token string) error {
	now := time.Now().UTC()
	from := now.AddDate(0, 0, -c.cfg.DailyLookback)
	to := now.AddDate(0, 0, -1)
	endpoint, err := url.Parse(c.cfg.BaseURL + "/api/v2/stats/daily")
	if err != nil {
		return err
	}
	query := endpoint.Query()
	query.Set("from", from.Format("20060102"))
	query.Set("to", to.Format("20060102"))
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	var daily []auth0DailyStats
	if _, err := c.doJSON(request, &daily); err != nil {
		return err
	}

	activeRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api/v2/stats/active-users", nil)
	if err != nil {
		return err
	}
	activeRequest.Header.Set("Authorization", "Bearer "+token)
	var activeUsers int64
	if _, err := c.doJSON(activeRequest, &activeUsers); err != nil {
		return err
	}

	c.metrics.daily.Reset()
	for _, day := range daily {
		label := day.Date.UTC().Format("2006-01-02")
		c.metrics.daily.WithLabelValues(c.cfg.Environment, c.cfg.Node, label, "logins").Set(float64(day.Logins))
		c.metrics.daily.WithLabelValues(c.cfg.Environment, c.cfg.Node, label, "signups").Set(float64(day.Signups))
		c.metrics.daily.WithLabelValues(c.cfg.Environment, c.cfg.Node, label, "leaked_passwords").Set(float64(day.LeakedPasswords))
	}
	c.metrics.activeUsers.WithLabelValues(c.cfg.Environment, c.cfg.Node).Set(float64(activeUsers))
	return nil
}

func (c *auth0UsageCollector) doJSON(request *http.Request, output any) (http.Header, error) {
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return response.Header, fmt.Errorf("Auth0 %s %s returned %s: %s", request.Method, request.URL.Path, response.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(output); err != nil {
		return response.Header, fmt.Errorf("decode Auth0 %s: %w", request.URL.Path, err)
	}
	return response.Header, nil
}

func runAuth0UsageExporter() error {
	cfg, err := loadAuth0UsageConfig()
	if err != nil {
		return err
	}
	registry := prometheus.NewRegistry()
	collector, err := newAuth0UsageCollector(cfg, nil, registry)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go collector.run(ctx)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server := &http.Server{
		Addr:              cfg.HTTPAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("Auth0 usage exporter listening", "address", cfg.HTTPAddress)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
