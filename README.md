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
