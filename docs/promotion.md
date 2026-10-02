# Promotion kit / Kit de promotion

Ready-to-paste drafts for sharing Snitch. Post these from your own accounts —
the order below maximises traction (HN first for timing, Reddit next, then
evergreen listings).

Brouillons prêts à copier-coller. Postez-les depuis vos propres comptes —
l'ordre ci-dessous maximise la traction (HN d'abord, Reddit ensuite, puis
les listes evergreen).

---

## 1. Show HN — news.ycombinator.com/submit

**Title:**
```
Show HN: Snitch – see every connection your computer makes, 100% local
```

**Text (first comment):**
```
I built Snitch because I kept wondering what my machine was actually
talking to. It passively captures packets (libpcap, own parser — no
external dependencies), enriches them 100% locally (DNS, TLS SNI, offline
DB-IP Lite GeoIP, IEEE OUI vendor table) and draws a live force graph:
your computer at the center, LAN devices inside a dashed perimeter ring,
every remote host geolocated on an outer orbit + a world map.

What it does differently:
- Zero telemetry — loopback-only API behind a token, everything in
  SQLite with 24 h retention
- Privacy score + anomaly detection (port scans, beaconing, exfiltration)
- Process attribution — which app is talking, not just which IP
- No Scapy — ctypes→libpcap with an in-project parser (GPL-compatible)
- Fully bilingual EN/FR, one click
- SNITCH_DEMO=1 runs synthetic traffic for a safe preview — no root needed

Stack: Python/FastAPI/WebSockets backend, React/D3.js frontend, Electron
desktop app, Docker, one-click install via Pinokio. AGPL-3.0.

Repo: https://github.com/aixisstudio/Snitch
```

---

## 2. Reddit

### r/privacy — title + body
```
[Tool] Snitch – open-source, local-first network traffic visualizer (AGPL)

I made a privacy-first tool that shows every connection your computer
makes — live node graph + world map, all analysis on-device. No account,
no cloud, no telemetry: the API only listens on 127.0.0.1 behind a token,
and even geolocation is offline (bundled DB-IP Lite, CC BY 4.0).

It flags port scans, beaconing and possible exfiltration, shows which
process generates which traffic, and rates your exposure with a live
privacy score. Bilingual EN/FR.

https://github.com/aixisstudio/Snitch
```

### r/netsec — shorter, technical
```
Snitch — real-time traffic visualizer (ctypes→libpcap, own parser, AGPL)

Passive pcap → FastAPI/WebSockets → D3.js force graph. Anomaly heuristics
(port scan, beaconing, exfil), per-process attribution, passive LAN
discovery via ARP table (no active scans). Offline GeoIP only.
macOS/Windows/Linux. Demo mode (SNITCH_DEMO=1) needs no root.

https://github.com/aixisstudio/Snitch
```

### r/selfhosted & r/opensource & r/macapps — adapt from the r/privacy text.
(Rule of thumb: one post per subreddit per day, comment "I made this"
disclosure, be ready to answer questions for the first hours.)

---

## 3. Dev.to / Medium — article skeleton (EN)

**Title:** *I built a local-first Little Snitch alternative that shows every connection your computer makes*

Outline:
1. Hook: the question "who is my computer talking to right now?"
2. Screenshot/GIF of the graph (docs/assets/demo.gif)
3. Design choices: passive capture, zero telemetry, offline GeoIP,
   own parser instead of Scapy (license), token-auth loopback API
4. Features tour: force graph, world map, privacy score, anomaly
   detection, per-process attribution
5. Install: one line via Pinokio / Electron / Docker
6. Call for feedback + repo link
Tags: `opensource`, `privacy`, `networking`, `python`, `showdev`

---

## 4. AlternativeTo.net — listing draft

- **Name:** Snitch
- **Tagline:** Real-time network traffic visualizer — see every connection
  your computer makes. 100% local, no account, no telemetry.
- **Platforms:** Mac, Windows, Linux (Docker), self-hosted
- **Alternatives to list under:** Little Snitch, GlassWire, LuLu,
  Wireshark (adjacent)
- **Tags:** network-monitor, privacy, open-source, packet-capture
- **License:** Free, open source (AGPL-3.0)
- **Website:** https://github.com/aixisstudio/Snitch
- **Developer:** aiXis — https://aixis.fr/

---

## 5. Awesome lists — submitted via PR

- `awesome-pcaptools` — traffic analysis tools (PR opened / en cours)
- Check the repo's own PR list for status.
