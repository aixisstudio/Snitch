[English](see-every-connection.md) | [Español](see-every-connection.es.md) | [Deutsch](see-every-connection.de.md) | [Русский](see-every-connection.ru.md) | [日本語](see-every-connection.ja.md) | [Português](see-every-connection.pt-BR.md) | [中文](see-every-connection.zh-CN.md)

Your computer is talking to the internet right now. Probably dozens of connections — sync, telemetry, update checks, your open tabs, your apps' background chatter. The question "what is my machine actually doing?" sounds basic, but try answering it and you'll find the tooling is either microscopic (Wireshark) or paywalled.

Here's a practical guide to actually seeing it — including the tool I built for it, [Snitch](https://github.com/aixisstudio/Snitch) (open source, AGPL — disclosure, it's mine).

## The 60-second version

```bash
# macOS / Linux — classic but raw
sudo tcpdump -i any -n | head -50        # every packet, no context
netstat -anp tcp | grep ESTABLISHED      # current connections only
lsof -i -nP | head                       # process → socket mapping

# Windows
netstat -ano | findstr ESTABLISHED
Get-NetTCPConnection -State Established  # PowerShell
```

These answer "what connections exist right now". They don't tell you which app, where the server is, or whether it's suspicious. That gap is exactly what a visualizer fills.

## The visualization approach

Snitch renders every connection as a live graph + world map:

- **Node = your machine** at the center, lines to every remote endpoint
- **Each endpoint labeled**: hostname (via reverse DNS + TLS SNI), geolocated country/city — all offline, from a local MaxMind/DB-IP database
- **Per-app attribution**: the connection is drawn to the *process* that opened it
- **Timeline**: 15/30/60-min traffic volume, 24h of history in a local SQLite file

What makes it different from tcpdump: the data is *already processed*. Not "packet to 142.250.74.78" — "Chrome → google.com → Frankfurt".

## Reading the map: normal vs suspicious

What a normal map looks like: spokes to Apple/Google/Microsoft/your browser tabs' CDNs, your router, other LAN devices.

What stands out:

- **Beaconing** — a connection that fires at regular intervals (Snitch flags these; it's a classic C2 pattern)
- **Long-lived uploads to unfamiliar endpoints** — data leaving steadily to somewhere you don't recognize
- **Port scans** — a LAN host touching many ports on your machine gets flagged
- **Apps talking to countries that make no sense** for what the app does
- **Trackers** — Snitch cross-references hostnames against editable tracker suffix lists and factors them into a privacy score

The built-in **anomaly detection** watches for all of these automatically, and you can suppress alerts per-rule once you've vetted a pattern.

## Install it (2 minutes)

```bash
# macOS: download the app from releases, or brew
# Windows: install Npcap → run snitch-backend.exe as Admin
# Linux / Docker:
docker run --network host ghcr.io/aixisstudio/snitch

# No admin rights? Demo mode shows the full UI with synthetic traffic:
SNITCH_DEMO=1 snitch-backend
```

Everything stays local — token-authenticated API bound to loopback, zero telemetry, no account, and every outbound call (GeoIP download, updates, threat intel, webhooks) is opt-in. That's not a marketing line; it's an AGPL codebase, you can verify the network code path yourself.

And when something looks wrong, you can act on it — since v1.2, Snitch pushes block rules into the OS-native firewall (netsh / iptables / pf), has a one-click lockdown switch, kill/suspend buttons, and a forensics export (JSON/CSV/STIX) for what you caught.

## Then what?

Once you can *see* the traffic, the interesting part starts — the community's favorite pastime is the ["What did you catch?" thread](https://github.com/aixisstudio/Snitch/discussions/39): printers talking to cloud servers at 3am, TV telemetry, the works.

Repo: https://github.com/aixisstudio/Snitch — ⭐ if it answers the question it set out to answer.
