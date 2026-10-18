# Drafts launch-day — tout copiable-collable

## Show HN repost (titre différent — l'histoire, pas la feature)

**Titre :** `Show HN: I open-sourced a network monitor and strangers shipped the Windows port`

**URL :** `https://github.com/aixisstudio/Snitch`

**Commentaire auteur :**

```
Author here. Snitch shows every connection your computer makes,
live on a world map — which apps talk to which servers, with
geolocation, process attribution, anomaly detection and a privacy
score. Everything stays on your machine: no account, no telemetry,
token-authenticated API bound to loopback.

Fun story: the Windows port wasn't me. Users filed bug reports
with root-cause analysis, then a stranger sent 3 PRs fixing it.
Cross-platform now: macOS (app + brew), Windows (exe + Npcap),
Linux (Docker image on GHCR).

Stack: Python + FastAPI + WebSockets, packet capture via
ctypes → libpcap/Npcap (no Scapy), custom IPv4/IPv6/TCP/UDP/
DNS/TLS-SNI parsing, offline MaxMind/DB-IP geolocation,
React + D3 frontend. AGPL, bilingual EN/FR + Chinese README.

Happy to answer anything — especially the capture pipeline.
```

## X / Twitter (jour J, avec la vidéo)

```
Your computer talks to ~200 servers a day. Do you know which ones?

Snitch maps every connection live — free, open source, 100% local.
Now on Product Hunt + the Windows port just shipped (built by the community!).

⭐ if useful: github.com/aixisstudio/Snitch
```

## LinkedIn (jour J)

```
🇬🇧 Your computer quietly talks to hundreds of servers a day.
Snitch makes that visible: a live map of every connection your
machine makes — which app, which server, which country.
Free, open-source (AGPL), 100% local, no account.

🇫🇷 Votre ordinateur parle à des centaines de serveurs par jour
sans que vous le sachiez. Snitch rend ça visible : carte live
de chaque connexion — quelle app, quel serveur, quel pays.
Gratuit, open source (AGPL), 100% local, sans compte.

Today on Product Hunt. macOS, Windows, Linux — and the Windows
port was contributed by strangers from the community. ⭐ on
GitHub if useful → github.com/aixisstudio/Snitch
```

## Reddit r/selfhosted (mardi ~14h)

**Titre :** `Snitch — self-hosted network traffic visualizer: see every connection your machine makes (Docker, AGPL)`

```
I built Snitch because I wanted Little Snitch's visibility
without the macOS lock-in — and without any cloud account.

- Live map of every connection: app → server → country
- Anomaly detection: port scans, beaconing, exfil patterns
- Process attribution + bandwidth per app
- 100% local: SQLite, token-authenticated API on loopback,
  zero telemetry, no outbound calls except opt-in GeoIP DB
- Docker: docker run --network host ghcr.io/aixisstudio/snitch
- macOS app + Windows exe too (Windows port was contributed
  by the community)

Demo mode if you want to try without root: SNITCH_DEMO=1

github.com/aixisstudio/Snitch — feedback welcome, and a ⭐
if it's useful to you.
```

## Reddit r/Python (jeudi — espacé, angle technique)

**Titre :** `I built a real-time packet analyzer in pure Python — ctypes → libpcap, no Scapy needed`

```
Snitch is an open-source network monitor I wrote in Python:
- Raw packet capture via ctypes → libpcap/Npcap
- Hand-rolled IPv4/IPv6/TCP/UDP/DNS/TLS-SNI parsing
- FastAPI + WebSocket backend streaming to a D3 map
- SQLite ring buffer, anomaly detection heuristics

The interesting bit: skipping Scapy entirely — ctypes bindings
are lighter, faster, and give exact control over packet fields.
The full pipeline is ~2K lines.

Repo: github.com/aixisstudio/Snitch (AGPL)
Happy to answer technical questions about the parser.
```

## Commentaire PH (à poster soi-même au lancement)

```
Maker here 👋 Snitch started from a simple frustration: my
computer was talking to hundreds of servers daily and I had
no idea which ones. It's a visualizer, not a firewall —
it shows you, doesn't decide for you.

Everything local: no account, no telemetry, API on loopback
with token auth. The Windows port was contributed by strangers
from the community — still blows my mind.

Ask me anything — technical details welcome (ctypes → libpcap
capture, no Scapy, custom protocol parsing).
```

## Answers evergreen (Q&A — à poster quand trouvé)

Modèle pour Quora/Super User/Reddit « Little Snitch alternative » :

```
If you're on Windows or Linux, Little Snitch doesn't exist —
closest options:

• Snitch (open source, free): real-time map of every connection,
  app → server → country, anomaly detection, 100% local. It's a
  visualizer though — it shows traffic, doesn't block it.
  github.com/aixisstudio/Snitch

• For actual blocking on Linux: OpenSnitch
• For Windows: Portmaster or GlassWire (freemium)
• For deep inspection: Wireshark

Honest take: Snitch answers "who is my machine talking to";
OpenSnitch/Portmaster answer "should it be allowed".
Different jobs — often complementary.
```

⚠️ Toujours lister des alternatives réelles — c'est ce qui rend la réponse légitime et durable.
