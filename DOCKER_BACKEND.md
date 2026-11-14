# Make Some Noise - Backend

The Go API server that generates synthetic security log events and metrics and delivers them to Syslog, Splunk HTTP Event Collector or files. The UI container is optional: everything it does is a REST call, so this image alone serves CI pipelines, Ansible roles and scripts.

## Quick Start

### Using Docker Compose

```bash
docker compose up -d
# API on http://localhost:8081 (bound to 127.0.0.1)
```

### Standalone

```bash
mkdir -p config output && sudo chown -R 1000:1000 config output
docker run -d \
  --name makesomenoise-backend \
  -p 127.0.0.1:8081:8080 \
  -e API_TOKEN=change-me \
  -v "$PWD/config:/config" \
  -v "$PWD/output:/tmp/output" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  thelawsofchaos/makesomenoise-backend:1.1.0
```

The image runs as uid 1000; the two bind mounts must be writable by it. Rootless Podman users add `:U` to each `-v`.

## Environment Variables

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | listen port inside the container |
| `CONFIG_DIR` | `/config` | `destinations.json` and `templates.json`, written 0600 |
| `OUTPUT_DIR` | `/tmp/output` | the only directory file destinations may write under |
| `API_TOKEN` | unset | when set, every `/api` route except `/api/health` needs `Authorization: Bearer <token>` |
| `GIN_MODE` | `release` | `debug` for per-request framework logging |

## Driving it from a pipeline

```bash
API=http://localhost:8081/api
AUTH="Authorization: Bearer $API_TOKEN"

# Create a HEC destination (the response masks the token)
DEST=$(curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $API/destinations -d '{
  "name": "lab splunk", "type": "hec",
  "config": {"url": "https://splunk:8088/services/collector/event", "token": "'"$HEC_TOKEN"'", "index": "noise"}
}' | jq -r .id)

# Test it
curl -s -H "$AUTH" -X POST $API/destinations/$DEST/test

# Send 500 Zeek connection events at 50 per second
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $API/generate -d '{
  "event_type": "zeek", "event_id": "conn", "count": 500, "rate_per_second": 50, "destination_id": "'"$DEST"'"
}'

# Or run background telemetry until stopped
curl -s -H "$AUTH" -H 'Content-Type: application/json' -X POST $API/noise/start -d '{
  "destination_id": "'"$DEST"'", "rate_per_second": 20,
  "enabled_sources": [{"event_type_id": "windows_security", "enabled": true, "weight": 10},
                      {"event_type_id": "zeek", "enabled": true, "weight": 10}]
}'
curl -s -H "$AUTH" $API/noise/status | jq '.skipped_sources, .stats'
curl -s -H "$AUTH" -X POST $API/noise/stop
```

The noise run is not persisted: start it again after a container restart. The full route list and the request bodies are in the [README](https://github.com/TheLawsOfChaos/make-some-noise/blob/main/README.md#api).

## Event sources

27 sources, 179 templates. The authoritative list is `GET /api/event-sources`; the README has it in prose. Windows Security and Sysmon, Microsoft AD, CrowdStrike, Defender, Linux Auditbeat, Okta, Azure AD sign-in, AWS CloudTrail, GuardDuty, VPC Flow and ALB, Azure Activity, Office 365, Kubernetes audit, Cisco ASA and Firepower, Palo Alto, Suricata, Zeek, DNS, web server access logs, VMware vCenter, and system, application, database and web metrics.

## Delivery

- **Syslog UDP or TCP**: RFC 3164 or 5424, one message per event, hostname from the event, reconnects after a failed write; plain text only.
- **Splunk HEC**: batches of `batch_size` (default 100) or whatever is buffered after one second; failed batches retried with backoff; buffer capped at ten batches with a `total_dropped` counter; TLS verified unless `insecure_skip_verify` is set; redirects refused.
- **File**: one event per line under `OUTPUT_DIR`, size-based rotation.

## Security notes

- Without `API_TOKEN` the API is open to anyone who can reach the port, which is why compose binds it to 127.0.0.1.
- HEC tokens are stored in clear text in `CONFIG_DIR/destinations.json` (mode 0600) and never returned by the API.
- A destination test connects to whatever host is configured; keep the API on a trusted network or behind the token.
- The container runs as uid 1000 with a read-only root filesystem and no capabilities when started from the compose file.

## Architecture

- Go 1.26, Gin, no CGO (static binary, about 30 MB image on Alpine)
- `backend/generators`: one file per source implementing `GetEventType`, `GetTemplates`, `Generate`
- `backend/delivery`: one file per sink implementing `Send`, `Test`, `Close`
- `backend/noise`: the continuous run (one ticker, weighted template choice)

## Troubleshooting

- **401 on every call**: `API_TOKEN` is set on the backend; send `Authorization: Bearer <token>`.
- **Nothing is generated after a restart**: expected; start the run again.
- **A source is missing from the stats**: `GET /api/noise/status` lists it under `skipped_sources` with the reason (unknown type, no destination, destination not in the start request, unknown template).
- **HEC sends fail with a certificate error**: the collector has a self-signed certificate; set `insecure_skip_verify: true` on the destination.
- **`total_dropped` grows**: the collector is down or slower than the rate; the buffer holds ten batches.
- **permission denied on /config or /tmp/output**: the bind mounts are not writable by uid 1000.
- Logs: `docker logs makesomenoise-backend`.

## License

Apache License 2.0, see [LICENSE](https://github.com/TheLawsOfChaos/make-some-noise/blob/main/LICENSE).
