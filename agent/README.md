# snitch-agent — lightweight remote sensor / capteur distant léger

**EN:** A zero-dependency Rust daemon that watches the host's socket
table (`/proc/net/*`, Linux) and pushes newly-observed outbound flows to
a Snitch collector's `POST /ingest/events` — contract `snitch-agent/1`.
One `cargo build --release` produces a single ~1 MB binary with no
runtime deps, so it deploys via a plain file copy or `nfpm`.

Scope, honestly:

- it observes **sockets**, it does not sniff packets — no payloads, no
  SNI/DNS; the collector's own capture keeps those duties;
- process attribution (`/proc/*/fd` walk) is a marked TODO in
  `src/main.rs`, not half-implemented;
- transport is plain HTTP + bearer — same trust-domain model as
  `gossip_peers`; tunnel over WireGuard/TLS on hostile links.

**FR :** Un daemon Rust sans dépendance qui surveille la table de
sockets de l'hôte (`/proc/net/*`, Linux) et pousse les nouveaux flux
sortants vers `POST /ingest/events` du collecteur — contrat
`snitch-agent/1`. Un seul `cargo build --release` → binaire ~1 Mo sans
dépendance runtime, déployable par simple copie ou `nfpm`.

Périmètre honnête : SOCKETS seulement (pas de payloads/SNI/DNS),
attribution de processus en TODO explicite dans `src/main.rs`, transport
HTTP + bearer (même modèle de confiance que `gossip_peers`).

## Build & run / Compiler & lancer

```bash
cargo build --release
SNITCH_SERVER="collector:8000" \
SNITCH_TOKEN="<collector api token>" \
SNITCH_HOST="agent-01" \
./target/release/snitch-agent
```

## systemd / service

`deploy/systemd/snitch-agent.service` runs it unprivileged — the agent
only needs to read `/proc/net`, no capabilities at all.

## Wire format / format fil

```json
POST /ingest/events   Authorization: Bearer <token>
{"agent":"snitch-agent/1","host":"agent-01","events":[
 {"ts":1718000000,"src_ip":"10.0.0.5","dst_ip":"93.184.216.34",
  "src_port":51822,"dst_port":443,"proto":"tcp","direction":"out",
  "bytes":0,"process":"","pid":0,"sni":""}]}
```

`bytes`, `process`, `pid` are `0`/empty until the TODOs land — the
collector still applies the full custom-rules surface to every event.
