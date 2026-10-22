[English](little-snitch-alternative-linux.md) | [Español](little-snitch-alternative-linux.es.md) | [Deutsch](little-snitch-alternative-linux.de.md) | [Русский](little-snitch-alternative-linux.ru.md) | [日本語](little-snitch-alternative-linux.ja.md) | [Português](little-snitch-alternative-linux.pt-BR.md) | [中文](little-snitch-alternative-linux.zh-CN.md)

Your computer talks to hundreds of servers a day. On Linux the classic answers are `tcpdump`, `ss`, `netstat`, or Wireshark — powerful, but they answer "show me packets", not "who is my machine talking to, and should I worry?".

I built [Snitch](https://github.com/aixisstudio/Snitch) for that second question — an open-source (AGPL) real-time network visualizer, and it's fully supported on Linux via Docker or the release binary. Full disclosure: I'm the author, so here's an honest rundown of what exists and where Snitch fits.

## The Linux landscape

| Tool | What it does | What it doesn't |
|---|---|---|
| **tcpdump / ss / netstat** | Raw connection data | No UI, no history, no geolocation, no app mapping |
| **Wireshark** | Deep packet dissection | Overkill for "who's phoning home" — it's a microscope, not a dashboard |
| **OpenSnitch** | Application firewall (block/allow prompts) | Minimal visualization — it's block-first, and it's Linux-only |
| **iftop / nethogs / nload** | Per-interface or per-process bandwidth | No world map, no anomaly detection, no persistence |
| **Snitch** | Live map of every connection: app → server → country, anomaly detection, 24h history, opt-in blocking via the OS firewall | OS-rule application is best-effort (needs privileges); not a full interactive firewall |

OpenSnitch and Snitch are complementary, not competitors: OpenSnitch is a mature interactive application firewall, Snitch shows you *what* your machine is doing — and since v1.2 can also push rules (`ip`/`cidr`/`domain`/`process`/`port`) into `iptables` plus a lockdown switch, best-effort.

## What Snitch gives you on Linux

- **Live world map** of every outbound connection, with process attribution — which app opened it, not just which IP
- **Offline geolocation** via a local MaxMind/DB-IP database — your IPs never leave the machine
- **Anomaly detection**: port scans on your LAN, beaconing (regular-interval callbacks, a classic C2 pattern), unusual outbound volume
- **Privacy score** + tracker detection from editable suffix lists
- **Per-app bandwidth**, timeline, 24h SQLite retention, alert suppression rules
- **Passive LAN scan** via the system ARP table — every device on your network, no packets injected
- **Outbound firewall rules + lockdown** — block an IP, CIDR, domain, process or port via the OS-native firewall (`iptables` on Linux), kill/suspend a process, export a forensics bundle (JSON/CSV/STIX)
- **Opt-in threat intel** — AbuseIPDB / AlienVault OTX / VirusTotal reputation checks with your own API key
- UI and docs in 8 languages (EN/FR/ES/DE/RU/JA/PT-BR/中文)

## The privacy part

This is the part Linux users tend to verify first, so: the API binds to **127.0.0.1** and requires a token. There is **no telemetry and no account**, and every outbound call — GeoIP download, update checks, threat-intel lookups, webhooks — is independently opt-in. Traffic data lives in a local SQLite file you own.

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
