Your computer talks to hundreds of servers a day. On Linux the classic answers are `tcpdump`, `ss`, `netstat`, or Wireshark — powerful, but they answer "show me packets", not "who is my machine talking to, and should I worry?".

I built [Snitch](https://github.com/aixisstudio/Snitch) for that second question — an open-source (AGPL) real-time network visualizer, and it's fully supported on Linux via Docker or the release binary. Full disclosure: I'm the author, so here's an honest rundown of what exists and where Snitch fits.

## The Linux landscape

| Tool | What it does | What it doesn't |
|---|---|---|
| **tcpdump / ss / netstat** | Raw connection data | No UI, no history, no geolocation, no app mapping |
| **Wireshark** | Deep packet dissection | Overkill for "who's phoning home" — it's a microscope, not a dashboard |
| **OpenSnitch** | Application firewall (block/allow prompts) | Minimal visualization — it's block-first, and it's Linux-only |
| **iftop / nethogs / nload** | Per-interface or per-process bandwidth | No world map, no anomaly detection, no persistence |
| **Snitch** | Live map of every connection: app → server → country, anomaly detection, 24h history | Doesn't block (by design — it's a visualizer) |

OpenSnitch and Snitch are complementary, not competitors: OpenSnitch decides *whether* a connection is allowed, Snitch shows you *what* your machine is doing.

## What Snitch gives you on Linux

- **Live world map** of every outbound connection, with process attribution — which app opened it, not just which IP
- **Offline geolocation** via a local MaxMind/DB-IP database — your IPs never leave the machine
- **Anomaly detection**: port scans on your LAN, beaconing (regular-interval callbacks, a classic C2 pattern), unusual outbound volume
- **Privacy score** + tracker detection from editable suffix lists
- **Per-app bandwidth**, timeline, 24h SQLite retention, alert suppression rules
- **Passive LAN scan** via the system ARP table — every device on your network, no packets injected
- Bilingual EN/FR UI (中文 README too)

## The privacy part

This is the part Linux users tend to verify first, so: the API binds to **127.0.0.1** and requires a token. There is **no telemetry, no account, no outbound call at all** except an explicitly consent-gated GeoIP database download. Traffic data lives in a local SQLite file you own.

## Install

```bash
# Docker (host networking needed for packet capture)
docker run --network host ghcr.io/aixisstudio/snitch

# or the release tarball — needs root/cap_net_raw like tcpdump
sudo ./snitch-backend
```

Then open the printed URL. There's also a demo mode (`SNITCH_DEMO=1`) that feeds synthetic traffic through the real pipeline if you want to look before granting capture rights.

## What's under the hood (for the curious)

Pure Python + ctypes → libpcap for capture — no Scapy dependency. The IPv4/IPv6/TCP/UDP/DNS/TLS-SNI parsing is hand-rolled, ~2K lines for the whole pipeline. FastAPI + WebSocket backend, React + D3 frontend, Electron shell on desktops.

If you want a "does my machine talk to weird places at 3am" answer on Linux without paying for a firewall or running a packet capture all day — that's exactly what this is for. ⭐ on [GitHub](https://github.com/aixisstudio/Snitch) if it earns it, and the repo's Discussions has a "what did you catch?" thread I'd love to see your screenshots in.
