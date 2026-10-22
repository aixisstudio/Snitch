# snitch-agent — lightweight remote sensor / capteur distant léger

**EN:** A zero-dependency Rust daemon that watches the host's socket
table (`/proc/net/*`, Linux) and pushes newly-observed outbound flows to
a Snitch collector's `POST /ingest/events` — contract `snitch-agent/1`.
One `cargo build --release` produces a single ~1 MB binary with no
runtime deps, so it deploys via a plain file copy or `nfpm`.

Scope, honestly:

- it observes **sockets**, it does not sniff packets — no payloads, no
  SNI/DNS; the collector's own capture keeps those duties;
- process attribution works on Linux: socket inodes are mapped to
  `pid`/`process` via a `/proc/*/fd` walk (`socket:[inode]` →
  `/proc/<pid>/comm`), built only when the socket diff is non-empty.
  Windows/macOS builds compile but report `pid: 0` until their
  `GetExtendedTcpTable`/`libproc` paths land — they are NOT silently
  wrong, just un-attributed;
- transport is plain HTTP — same trust-domain model as `gossip_peers`;
  tunnel over WireGuard/TLS on hostile links.

**FR :** Un daemon Rust sans dépendance qui surveille la table de
sockets de l'hôte (`/proc/net/*`, Linux) et pousse les nouveaux flux
sortants vers `POST /ingest/events` du collecteur — contrat
`snitch-agent/1`. Un seul `cargo build --release` → binaire ~1 Mo sans
dépendance runtime, déployable par simple copie ou `nfpm`.

Périmètre honnête : SOCKETS seulement (pas de payloads/SNI/DNS),
attribution de processus fonctionnelle sous Linux via `/proc/*/fd`
(reporte `pid: 0` sous Windows/macOS tant que leurs chemins
`GetExtendedTcpTable`/`libproc` ne sont pas livrés), transport HTTP.

## Enroll & run / Enrôler & lancer

```bash
# EN: mint a per-agent token on the collector (master token required)
# FR: mint un jeton par agent sur le collecteur (jeton maître requis)
curl -X POST http://collector:8000/ingest/enroll \
  -H "X-Snitch-Token: <master token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "agent-01"}'          # → {"token": "sagt_…"}  (shown once)

cargo build --release
SNITCH_SERVER="collector:8000" \
SNITCH_TOKEN="sagt_…" \
SNITCH_HOST="agent-01" \
./target/release/snitch-agent
```

`SNITCH_TOKEN` accepts either an enrolled `sagt_…` credential (sent as
`X-Snitch-Agent`, the enrolled name is authoritative — the agent cannot
spoof another) or the collector master token (sent as `X-Snitch-Token`).
Revoke with `POST /ingest/revoke {"name": "agent-01"}`.

## systemd / service

`deploy/systemd/snitch-agent.service` runs it unprivileged — the agent
only needs to read `/proc/net` + `/proc/*/fd`, no capabilities at all.

## CI

`.github/workflows/ci-agent.yml` compiles and unit-tests on
`x86_64-unknown-linux-gnu`, `x86_64-apple-darwin` and
`x86_64-pc-windows-msvc` on every `agent/**` push.

## Wire format / format fil

```json
POST /ingest/events   X-Snitch-Agent: sagt_…
{"agent":"snitch-agent/1","host":"agent-01","events":[
 {"ts":1718000000,"src_ip":"10.0.0.5","dst_ip":"93.184.216.34",
  "src_port":51822,"dst_port":443,"proto":"tcp","direction":"out",
  "bytes":0,"process":"curl","pid":1337,"sni":""}]}
```

`process`/`pid` are filled on Linux, `0`/empty elsewhere. The collector
still applies the full custom-rules surface to every event.
