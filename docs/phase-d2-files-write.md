# Allowlisted file writes

The default executor stays `noop`. This page describes when a file write may dial Wings. It does not put a daemon token in the tree.

## What dials

`PUT /v1/servers/{uuid}/files/content?path=…` dials Wings only when all of these hold:

- `PANEL_WINGS_EXECUTOR=real`
- `PANEL_WINGS_BASE_URL` and `PANEL_WINGS_TOKEN` are both set
- the path UUID is on `PANEL_WINGS_ALLOWLIST` (a node id does not authorize a write)
- the target is not a GlassHosting-managed server the caller does not own
- the path is under `mods/` or `plugins/` and the file name ends in `.jar` or `.zip`
- the body is a zip local-file archive (`PK\x03\x04`), at most 32 MiB

The daemon call is `POST {PANEL_WINGS_BASE_URL}/api/servers/{uuid}/files/write` with `Authorization: Bearer` and `Content-Type: application/octet-stream`. `X-Request-Id` is copied onto the Wings request.

A completed round trip sets `X-Glass-Wings-Dispatch: 1`. A Wings non-2xx is **502** `wings_rejected`. A missing daemon origin is **502** `wings_dial_failed` with dispatch **0**.

`DELETE` on the same route uses the same gates and dials the daemon delete route for that one file.

## What does not dial

| Case | Response | Dispatch |
|------|----------|----------|
| GlassHosting-managed server the caller does not own | **403** | **0** |
| `PANEL_WINGS_EXECUTOR=noop` | **403** `test_files_write_disabled` | **0** |
| Empty allowlist | **403** `wings_allowlist_empty` | **0** |
| UUID not on `PANEL_WINGS_ALLOWLIST` | **403** `wings_uuid_not_allowlisted` | **0** |
| `../`, a host path, a unit path, or a file outside `mods/` and `plugins/` | **400** `path_not_allowlisted` | **0** |
| Body that is not a zip or jar archive | **400** `content_not_archive` | **0** |

Path checks run before any dial. Redirects are not followed. The daemon token is not logged.

Idempotency replay does not dial a second time. Create, power, backups, migrations, and console tickets are unchanged. See [`phase-c-wings-allowlist.md`](phase-c-wings-allowlist.md).
