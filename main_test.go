package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	accesslogdata "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func testServer(t *testing.T, staticJSON, keyFile string) *server {
	t.Helper()
	ids, err := newIdentityStore(staticJSON, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{
		Environment: "dev1", Node: "validator-dev1",
		AllowedServices:  map[string]struct{}{"ledger": {}, "dar": {}},
		AllowedProtocols: map[string]struct{}{"http": {}, "grpc": {}},
		Routes: map[string]routeMetadata{
			"canton-ledger-http": {Service: "ledger", Protocol: "http"},
			"canton-ledger-grpc": {Service: "ledger", Protocol: "grpc"},
			"canton-dar-upload":  {Service: "dar", Protocol: "http"},
		},
	}
	return &server{cfg: cfg, ids: ids, stats: newMetrics(prometheus.NewRegistry())}
}

func checkRequest(headers map[string]string, route string) *authv3.CheckRequest {
	resource, _ := structpb.NewStruct(map[string]any{"name": route})
	resources, _ := structpb.NewList([]any{resource.AsMap()})
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Headers: headers}},
		RouteMetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
			"envoy-gateway": {Fields: map[string]*structpb.Value{"resources": structpb.NewListValue(resources)}},
		}},
	}}
}

func TestCheckMapsJWTIdentityAndOverwritesClientHeader(t *testing.T) {
	s := testServer(t, `{"auth0-id":"openzeppelin"}`, "")
	response, err := s.Check(context.Background(), checkRequest(map[string]string{
		identityHeader: "auth0-id", clientHeader: "attacker", serviceHeader: "dar", protocolHeader: "http",
	}, "canton-ledger-grpc"))
	if err != nil || response.GetOkResponse() == nil {
		t.Fatalf("expected allow response: response=%v err=%v", response, err)
	}
	if got := response.GetOkResponse().GetHeaders()[0].GetHeader().GetValue(); got != "openzeppelin" {
		t.Fatalf("client header = %q", got)
	}
	for i, want := range []struct{ key, value string }{
		{clientHeader, "openzeppelin"}, {serviceHeader, "ledger"}, {protocolHeader, "grpc"},
	} {
		header := response.GetOkResponse().GetHeaders()[i]
		if header.GetHeader().GetKey() != want.key || header.GetHeader().GetValue() != want.value {
			t.Fatalf("header %d = %s:%s, want %s:%s", i, header.GetHeader().GetKey(), header.GetHeader().GetValue(), want.key, want.value)
		}
		if header.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Fatalf("header %s does not overwrite an inbound value", want.key)
		}
	}
}

func TestCheckMapsDARKeyAndReloadsRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`{"first-secret":"openzeppelin"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, `{}`, path)
	request := func(key string) *authv3.CheckRequest {
		return checkRequest(map[string]string{
			"authorization": "Bearer " + key, serviceHeader: "dar", protocolHeader: "http",
		}, "canton-dar-upload")
	}
	if response, _ := s.Check(context.Background(), request("first-secret")); response.GetOkResponse() == nil {
		t.Fatal("expected initial key to be accepted")
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte(`{"second-secret":"openzeppelin"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if response, _ := s.Check(context.Background(), request("second-secret")); response.GetOkResponse() == nil {
		t.Fatal("expected rotated key to be accepted")
	}
	if response, _ := s.Check(context.Background(), request("first-secret")); response.GetDeniedResponse() == nil {
		t.Fatal("expected retired key to be denied")
	}
}

func TestCheckMapsDARRichAPIKeyEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`{
		"object-secret":{"name":"client-1","party":"client1-demo::1220deadbeef"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, `{}`, path)
	response, err := s.Check(context.Background(), checkRequest(map[string]string{
		"authorization": "Bearer object-secret",
	}, "canton-dar-upload"))
	if err != nil || response.GetOkResponse() == nil {
		t.Fatalf("expected rich API key entry to be accepted: response=%v err=%v", response, err)
	}
	if got := response.GetOkResponse().GetHeaders()[0].GetHeader().GetValue(); got != "client-1" {
		t.Fatalf("client header = %q, want client-1", got)
	}
}

func TestAPIKeyMappingRejectsObjectWithoutNormalizedName(t *testing.T) {
	for name, data := range map[string]string{
		"missing": `{"secret":{"party":"client1-demo::1220deadbeef"}}`,
		"invalid": `{"secret":{"name":"Client 1","party":"client1-demo::1220deadbeef"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAPIKeyMapping([]byte(data)); err == nil {
				t.Fatal("expected invalid rich API key entry to be rejected")
			}
		})
	}
}

func TestCheckRejectsUnknownAndInvalidMetadata(t *testing.T) {
	s := testServer(t, `{"known":"openzeppelin"}`, "")
	for name, headers := range map[string]map[string]string{
		"unknown": {identityHeader: "unknown", serviceHeader: "ledger", protocolHeader: "http"},
		"spoofed": {identityHeader: "known", serviceHeader: "dar", protocolHeader: "http"},
	} {
		t.Run(name, func(t *testing.T) {
			route := "canton-ledger-http"
			if name == "spoofed" {
				route = "unknown-route"
			}
			response, err := s.Check(context.Background(), checkRequest(headers, route))
			if err != nil || response.GetDeniedResponse() == nil {
				t.Fatalf("expected deny response: response=%v err=%v", response, err)
			}
		})
	}
}

func TestObserveExportsOnlyBoundedAttributedMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	cfg := config{
		Environment: "dev1", Node: "validator-dev1",
		AllowedServices:  map[string]struct{}{"ledger": {}},
		AllowedProtocols: map[string]struct{}{"grpc": {}},
	}
	s := &server{cfg: cfg, stats: newMetrics(registry)}
	ids, err := newIdentityStore(`{"id":"openzeppelin"}`, "")
	if err != nil {
		t.Fatal(err)
	}
	s.ids = ids
	s.observe(&accesslogdata.HTTPAccessLogEntry{
		Request: &accesslogdata.HTTPRequestProperties{RequestHeaders: map[string]string{
			clientHeader: "openzeppelin", serviceHeader: "ledger", protocolHeader: "grpc",
		}},
		Response: &accesslogdata.HTTPResponseProperties{
			ResponseCode: wrapperspb.UInt32(200), ResponseTrailers: map[string]string{"grpc-status": "0"},
		},
		CommonProperties: &accesslogdata.AccessLogCommon{Duration: durationpb.New(250 * time.Millisecond)},
	})
	if got := testutil.ToFloat64(s.stats.requests.WithLabelValues("dev1", "validator-dev1", "openzeppelin", "ledger", "grpc", "2xx", "0")); got != 1 {
		t.Fatalf("request metric = %v", got)
	}

	s.observe(&accesslogdata.HTTPAccessLogEntry{
		Request: &accesslogdata.HTTPRequestProperties{RequestHeaders: map[string]string{
			clientHeader: "unmapped-client", serviceHeader: "ledger", protocolHeader: "grpc",
		}},
		Response: &accesslogdata.HTTPResponseProperties{ResponseCode: wrapperspb.UInt32(200)},
	})
	if got := testutil.ToFloat64(s.stats.alsDropped); got != 1 {
		t.Fatalf("dropped metric = %v", got)
	}
}

func TestHeaderOptionDefaultsToOverwrite(t *testing.T) {
	option := &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: clientHeader, Value: "openzeppelin"}}
	if option.GetAppend().GetValue() {
		t.Fatal("trusted attribution header must overwrite client-supplied values")
	}
}
