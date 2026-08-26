package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	accesslogdata "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	clientHeader   = "x-canton-client"
	identityHeader = "x-canton-auth-client-id"
	serviceHeader  = "x-canton-service"
	protocolHeader = "x-canton-protocol"
)

var normalizedLabel = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

type config struct {
	Environment      string
	Node             string
	GRPCAddress      string
	HTTPAddress      string
	IdentityMapJSON  string
	APIKeysFile      string
	Routes           map[string]routeMetadata
	AllowedServices  map[string]struct{}
	AllowedProtocols map[string]struct{}
}

type routeMetadata struct {
	Service  string
	Protocol string
}

func loadConfig() (config, error) {
	cfg := config{
		Environment:      envOr("ENVIRONMENT", "dev1"),
		Node:             envOr("NODE", "validator-dev1"),
		GRPCAddress:      envOr("GRPC_ADDRESS", ":9001"),
		HTTPAddress:      envOr("HTTP_ADDRESS", ":9090"),
		IdentityMapJSON:  os.Getenv("AUTH0_CLIENTS_JSON"),
		APIKeysFile:      os.Getenv("API_KEYS_FILE"),
		AllowedServices:  csvSet(envOr("ALLOWED_SERVICES", "ledger,dar")),
		AllowedProtocols: csvSet(envOr("ALLOWED_PROTOCOLS", "http,grpc")),
	}
	if err := json.Unmarshal([]byte(envOr("ROUTES_JSON", `{}`)), &cfg.Routes); err != nil {
		return config{}, fmt.Errorf("ROUTES_JSON: %w", err)
	}
	if !normalizedLabel.MatchString(cfg.Environment) || !normalizedLabel.MatchString(cfg.Node) {
		return config{}, errors.New("ENVIRONMENT and NODE must be bounded label values")
	}
	if len(cfg.AllowedServices) == 0 || len(cfg.AllowedProtocols) == 0 {
		return config{}, errors.New("ALLOWED_SERVICES and ALLOWED_PROTOCOLS must not be empty")
	}
	for name, route := range cfg.Routes {
		if !normalizedLabel.MatchString(name) {
			return config{}, errors.New("ROUTES_JSON contains an invalid route name")
		}
		if _, ok := cfg.AllowedServices[route.Service]; !ok {
			return config{}, errors.New("ROUTES_JSON contains a service outside ALLOWED_SERVICES")
		}
		if _, ok := cfg.AllowedProtocols[route.Protocol]; !ok {
			return config{}, errors.New("ROUTES_JSON contains a protocol outside ALLOWED_PROTOCOLS")
		}
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func csvSet(value string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if normalizedLabel.MatchString(item) {
			result[item] = struct{}{}
		}
	}
	return result
}

type identityStore struct {
	static map[string]string
	path   string
	mu     sync.RWMutex
	mtime  time.Time
	keys   map[string]string
}

func newIdentityStore(staticJSON, path string) (*identityStore, error) {
	static, err := parseMapping([]byte(staticJSON), true)
	if err != nil {
		return nil, fmt.Errorf("AUTH0_CLIENTS_JSON: %w", err)
	}
	s := &identityStore{static: static, path: path, keys: map[string]string{}}
	if path != "" {
		if err := s.reloadKeys(); err != nil {
			return nil, err
		}
	}
	if len(static) == 0 && path == "" {
		return nil, errors.New("at least one identity mapping source is required")
	}
	return s, nil
}

func parseMapping(data []byte, allowEmpty bool) (map[string]string, error) {
	result := make(map[string]string)
	if strings.TrimSpace(string(data)) == "" && allowEmpty {
		return result, nil
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("must be a JSON object of credential to normalized client: %w", err)
	}
	if len(result) == 0 && !allowEmpty {
		return nil, errors.New("mapping must not be empty")
	}
	for credential, client := range result {
		if strings.TrimSpace(credential) == "" || !normalizedLabel.MatchString(client) {
			return nil, errors.New("mapping contains an empty credential or invalid normalized client")
		}
	}
	return result, nil
}

func (s *identityStore) reloadKeys() error {
	info, err := os.Stat(s.path)
	if err != nil {
		return fmt.Errorf("stat API_KEYS_FILE: %w", err)
	}
	s.mu.RLock()
	unchanged := info.ModTime().Equal(s.mtime)
	s.mu.RUnlock()
	if unchanged {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read API_KEYS_FILE: %w", err)
	}
	keys, err := parseMapping(data, false)
	if err != nil {
		return fmt.Errorf("API_KEYS_FILE: %w", err)
	}
	s.mu.Lock()
	s.keys = keys
	s.mtime = info.ModTime()
	s.mu.Unlock()
	return nil
}

func (s *identityStore) clientForIdentity(identity string) (string, bool) {
	client, ok := s.static[identity]
	return client, ok
}

func (s *identityStore) clientForAPIKey(key string) (string, bool, error) {
	if s.path == "" {
		return "", false, nil
	}
	if err := s.reloadKeys(); err != nil {
		return "", false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for candidate, client := range s.keys {
		if len(candidate) == len(key) && subtle.ConstantTimeCompare([]byte(candidate), []byte(key)) == 1 {
			return client, true, nil
		}
	}
	return "", false, nil
}

func (s *identityStore) knownClient(client string) bool {
	for _, candidate := range s.static {
		if candidate == client {
			return true
		}
	}
	if s.path == "" || s.reloadKeys() != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, candidate := range s.keys {
		if candidate == client {
			return true
		}
	}
	return false
}

type metrics struct {
	requests      *prometheus.CounterVec
	admitted      *prometheus.CounterVec
	duration      *prometheus.HistogramVec
	authDecisions *prometheus.CounterVec
	alsDropped    prometheus.Counter
	gatewayUp     *prometheus.GaugeVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "canton_api_requests_total",
			Help: "Completed contractual Canton API requests observed by Envoy.",
		}, []string{"environment", "node", "client", "service", "protocol", "status_class", "grpc_status"}),
		admitted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "canton_api_admitted_requests_total",
			Help: "Contractual Canton API requests synchronously admitted by the gateway.",
		}, []string{"environment", "node", "client", "service", "protocol"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "canton_api_request_duration_seconds",
			Help:    "End-to-end duration of completed contractual Canton API requests.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"environment", "node", "client", "service", "protocol", "status_class", "grpc_status"}),
		authDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "canton_api_auth_decisions_total",
			Help: "Gateway authorization decisions without credential labels.",
		}, []string{"environment", "node", "service", "protocol", "decision", "reason"}),
		alsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "canton_api_als_entries_dropped_total",
			Help: "Access log entries ignored because bounded attribution metadata was absent or invalid.",
		}),
		gatewayUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "canton_api_gateway_up",
			Help: "Whether this auth and metrics service process is ready to serve requests.",
		}, []string{"environment", "node"}),
	}
	reg.MustRegister(m.requests, m.admitted, m.duration, m.authDecisions, m.alsDropped, m.gatewayUp)
	return m
}

type server struct {
	authv3.UnimplementedAuthorizationServer
	accesslogv3.UnimplementedAccessLogServiceServer
	cfg   config
	ids   *identityStore
	stats *metrics
}

func (s *server) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpRequest := req.GetAttributes().GetRequest().GetHttp()
	if httpRequest == nil {
		return s.deny("unknown", "unknown", "invalid_request", typev3.StatusCode_BadRequest), nil
	}
	headers := lowerHeaders(httpRequest.GetHeaders())
	service, protocol := s.routeAttribution(req)
	if !s.allowedMetadata(service, protocol) {
		return s.deny(service, protocol, "invalid_metadata", typev3.StatusCode_Forbidden), nil
	}

	client, found := s.ids.clientForIdentity(headers[identityHeader])
	if !found && service == "dar" {
		key := bearerToken(headers["authorization"])
		var err error
		client, found, err = s.ids.clientForAPIKey(key)
		if err != nil {
			slog.Error("API key mapping reload failed", "error", err)
			return s.deny(service, protocol, "mapping_unavailable", typev3.StatusCode_ServiceUnavailable), nil
		}
	}
	if !found {
		return s.deny(service, protocol, "unmapped_identity", typev3.StatusCode_Forbidden), nil
	}

	s.stats.authDecisions.WithLabelValues(s.cfg.Environment, s.cfg.Node, service, protocol, "allow", "mapped_identity").Inc()
	s.stats.admitted.WithLabelValues(s.cfg.Environment, s.cfg.Node, client, service, protocol).Inc()
	overwrite := corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
			Headers: []*corev3.HeaderValueOption{
				{Header: &corev3.HeaderValue{Key: clientHeader, Value: client}, AppendAction: overwrite},
				{Header: &corev3.HeaderValue{Key: serviceHeader, Value: service}, AppendAction: overwrite},
				{Header: &corev3.HeaderValue{Key: protocolHeader, Value: protocol}, AppendAction: overwrite},
			},
			HeadersToRemove: []string{identityHeader},
		}},
	}, nil
}

func (s *server) routeAttribution(req *authv3.CheckRequest) (string, string) {
	metadata := req.GetAttributes().GetRouteMetadataContext().GetFilterMetadata()["envoy-gateway"]
	if metadata == nil {
		return "", ""
	}
	resources := metadata.GetFields()["resources"].GetListValue().GetValues()
	for _, resource := range resources {
		name := resource.GetStructValue().GetFields()["name"].GetStringValue()
		if route, ok := s.cfg.Routes[name]; ok {
			return route.Service, route.Protocol
		}
	}
	return "", ""
}

func (s *server) allowedMetadata(service, protocol string) bool {
	_, serviceOK := s.cfg.AllowedServices[service]
	_, protocolOK := s.cfg.AllowedProtocols[protocol]
	return serviceOK && protocolOK
}

func (s *server) deny(service, protocol, reason string, code typev3.StatusCode) *authv3.CheckResponse {
	if _, ok := s.cfg.AllowedServices[service]; !ok {
		service = "unknown"
	}
	if _, ok := s.cfg.AllowedProtocols[protocol]; !ok {
		protocol = "unknown"
	}
	s.stats.authDecisions.WithLabelValues(s.cfg.Environment, s.cfg.Node, service, protocol, "deny", reason).Inc()
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status: &typev3.HttpStatus{Code: code},
			Body:   "request is not authorized\n",
		}},
	}
}

func lowerHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers))
	for key, value := range headers {
		result[strings.ToLower(key)] = value
	}
	return result
}

func bearerToken(value string) string {
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

func (s *server) StreamAccessLogs(stream accesslogv3.AccessLogService_StreamAccessLogsServer) error {
	for {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&accesslogv3.StreamAccessLogsResponse{})
		}
		if err != nil {
			return err
		}
		for _, entry := range message.GetHttpLogs().GetLogEntry() {
			s.observe(entry)
		}
	}
}

func (s *server) observe(entry *accesslogdata.HTTPAccessLogEntry) {
	requestHeaders := lowerHeaders(entry.GetRequest().GetRequestHeaders())
	client := requestHeaders[clientHeader]
	service := requestHeaders[serviceHeader]
	protocol := requestHeaders[protocolHeader]
	if !normalizedLabel.MatchString(client) || !s.ids.knownClient(client) || !s.allowedMetadata(service, protocol) {
		s.stats.alsDropped.Inc()
		return
	}

	responseCode := entry.GetResponse().GetResponseCode().GetValue()
	statusClass := fmt.Sprintf("%dxx", responseCode/100)
	if responseCode < 100 || responseCode > 599 {
		statusClass = "unknown"
	}
	grpcStatus := "none"
	if protocol == "grpc" {
		grpcStatus = lowerHeaders(entry.GetResponse().GetResponseTrailers())["grpc-status"]
		if grpcStatus == "" {
			grpcStatus = lowerHeaders(entry.GetResponse().GetResponseHeaders())["grpc-status"]
		}
		if !isGRPCStatus(grpcStatus) {
			grpcStatus = "unknown"
		}
	}
	labels := []string{s.cfg.Environment, s.cfg.Node, client, service, protocol, statusClass, grpcStatus}
	s.stats.requests.WithLabelValues(labels...).Inc()
	if duration := entry.GetCommonProperties().GetDuration(); duration != nil && duration.IsValid() {
		s.stats.duration.WithLabelValues(labels...).Observe(duration.AsDuration().Seconds())
	}
}

func isGRPCStatus(value string) bool {
	switch value {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16":
		return true
	default:
		return false
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ids, err := newIdentityStore(cfg.IdentityMapJSON, cfg.APIKeysFile)
	if err != nil {
		return err
	}
	registry := prometheus.NewRegistry()
	s := &server{cfg: cfg, ids: ids, stats: newMetrics(registry)}
	up := s.stats.gatewayUp.WithLabelValues(cfg.Environment, cfg.Node)
	up.Set(1)

	grpcListener, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(4<<20),
		grpc.MaxConcurrentStreams(1024),
	)
	authv3.RegisterAuthorizationServer(grpcServer, s)
	accesslogv3.RegisterAccessLogServiceServer(grpcServer, s)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if cfg.APIKeysFile != "" {
			if err := ids.reloadKeys(); err != nil {
				up.Set(0)
				http.Error(w, "mapping unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		up.Set(1)
		w.WriteHeader(http.StatusOK)
	})
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		slog.Info("gRPC server listening", "address", cfg.GRPCAddress)
		errCh <- grpcServer.Serve(grpcListener)
	}()
	go func() {
		slog.Info("HTTP server listening", "address", cfg.HTTPAddress)
		errCh <- httpServer.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		up.Set(0)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		grpcServer.GracefulStop()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func main() {
	if err := run(); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, grpc.ErrServerStopped) {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
