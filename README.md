# Canton gateway auth and metrics

This bounded-cardinality service implements Envoy's gRPC `ext_authz` and
Access Log Service APIs. It maps trusted Auth0 identities (or DAR API keys) to
a normalized client name and exports completed request counters and latency.

Required configuration:

- `AUTH0_CLIENTS_JSON`: JSON map of Auth0 `client_id`/`azp` values to normalized clients.
- `API_KEYS_FILE`: optional JSON map of DAR API keys to normalized clients. Values may be
  client strings or DAR proxy entries such as `{"name":"client-1","party":"..."}`; the
  bounded `name` is used for metrics attribution and the party is ignored.
- `ENVIRONMENT`, `NODE`: constant metric labels.
- `ALLOWED_SERVICES`, `ALLOWED_PROTOCOLS`: bounded label allowlists.
- `ROUTES_JSON`: Envoy Gateway route-name map such as
  `{"canton-ledger-http":{"service":"ledger","protocol":"http"}}`.

The service never logs credentials and rejects any unmapped identity. Envoy
must remove inbound attribution headers before authentication and pass trusted
route metadata to `ext_authz`. On allow, this service overwrites
`x-canton-client`, `x-canton-service`, and `x-canton-protocol`; Envoy logs only
those trusted attribution headers to ALS.

Use `canton_api_admitted_requests_total` for usage-window monitoring because it
is incremented synchronously in ext_auth. `canton_api_requests_total` and
`canton_api_request_duration_seconds` come from Envoy ALS and add final HTTP and
gRPC outcome labels; ALS is intentionally lossy and should not be the billing
source of record.

Admission and authorization counters are initialized at zero for every bounded
configured client/route combination so idle gateways remain queryable and the
first scrape can establish the zero baseline used by Prometheus `increase()`
queries.

## Auth0 usage exporter mode

Set `SERVICE_MODE=auth0-usage-exporter` to run a metrics-only process that polls
the Auth0 Management API. Run one replica with durable storage; do not enable
this mode on every gateway replica, because each process would consume the same
tenant log stream.

Required configuration:

- `AUTH0_DOMAIN`: tenant hostname, without an API path.
- `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`: read-only Management API client with
  `read:logs` and `read:stats` grants.
- `AUTH0_USAGE_CLIENTS_JSON`: optional map of Auth0 client IDs to bounded client
  labels. Unmapped M2M exchanges are aggregated as `client="other"`.
- `AUTH0_USAGE_STATE_FILE`: durable log checkpoint and counter state; defaults
  to `/data/auth0-usage-state.json`.
- `AUTH0_USAGE_POLL_INTERVAL`: defaults to `5m` and cannot be less than `30s`.
- `AUTH0_USAGE_DAILY_LOOKBACK_DAYS`: daily-stat range, default and maximum `31`.
- `AUTH0_USAGE_MAX_LOG_PAGES`: maximum 100-entry log pages per poll; defaults to
  `10` so backlog catch-up cannot monopolize the tenant API.

The exporter emits:

- `auth0_m2m_token_exchanges_total` from `seccft` and `feccft` tenant logs.
- `auth0_tenant_daily_events` for logins, signups, and breached-password
  detections. Auth0 daily stats do not count M2M exchanges.
- `auth0_tenant_active_users` for the Auth0 30-day active-user statistic.
- `auth0_usage_collector_up`, `auth0_usage_last_success_timestamp_seconds`,
  `auth0_usage_collection_errors_total`, and checkpoint/process counters for
  detecting missing or stale collection.

On first startup, the exporter establishes a forward-only log checkpoint and
counts new log events from that point. It does not silently reinterpret the
tenant's retained log tail as a historical backfill. Daily statistics are
refreshed from Auth0 on every poll. HTTP 429 and other API failures are exposed
as collection errors without affecting gateway authorization.
