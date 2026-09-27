# Test runtime checklist

Spec: [`openapi/glass-game-panel-v1.openapi.yaml`](../openapi/glass-game-panel-v1.openapi.yaml), version `0.1.5-stub`.

`go test ./...` covers the items below. Spec text alone does not run the checks.

## Refuse

- [ ] A refused GlassHosting-managed server returns **403** `managed_inventory_denied` for power, files, console ticket, backups (including restore), delete, and server write
- [ ] An empty or over-broad agent server list still cannot reach those servers
- [ ] The refuse step runs before any Wings dial

## Import

- [ ] A client flag cannot pull refused servers into an import plan
- [ ] This build keeps that include flag false
- [ ] A remap cannot force a refused row

## Agent tokens

- [ ] Mint requires a non-empty `server_ids` list
- [ ] Migration scopes are not mintable on an agent token
- [ ] A refused server UUID in `server_ids` is rejected
- [ ] `ttl_seconds` is at most **3600**
- [ ] An agent token cannot mint another token

## Console ticket

- [ ] Ticket TTL is at most **120** seconds
- [ ] The ticket is single-use
- [ ] The ticket is bound to the server and the minting subject
- [ ] WebSocket auth is the ticket only. A bearer on the handshake is rejected
- [ ] Mint and upgrade refuse a GlassHosting-managed server the caller does not own

## Exposure

- [ ] The process listens on loopback by default
- [ ] Production audience and issuer tokens are rejected
- [ ] There is no anonymous OpenAPI UI
- [ ] The process enforces 60 mutate and 300 read requests per minute per token

## No unsolicited Wings dial

- [ ] Power, files, console, and backup restore do not dial for a refused server
- [ ] Auth checks, refuse responses, and an `inventory_only` plan against a server the caller may import are allowed
- [ ] The default executor does not dial Wings

The machine catalog is the embedded deny file the tests compare. It is not restated here.
