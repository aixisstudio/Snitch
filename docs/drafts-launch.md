# Drafts launch-day — tout copiable-collable

## Show HN repost — le vrai package « buzz »

**Timing : mardi 14h30-15h00 Paris** (= 8h30-9h New York, mardi ouvré = le meilleur créneau de la semaine). PAS avant : il faut que la front page US soit active.

**URL :** `https://github.com/aixisstudio/Snitch` (le repo — chaque visite peut devenir une étoile)

### Titre — option A (data hook, recommandé, 80/80 car.)

`Show HN: Snitch – my Mac talked to 347 servers in one idle hour, so I built this`

### Titre — option B (story hook, 79 car., si A a déjà été posté)

`Show HN: I open-sourced a network monitor — strangers shipped the Windows port`

### Premier commentaire auteur — à poster DANS LES 60 SECONDES après soumission

```
Author here. The seed of this project: I ran it for one idle hour
and my Mac had talked to 347 distinct servers across ~17
companies — 158 of them Google IPs. I wanted to *see* that, so I
built the tool.

Stack details for the curious:

- Capture: ctypes → libpcap directly, no Scapy. Own parsers for
  Ethernet/IPv4/IPv6/TCP/UDP/DNS/TLS-SNI. Windows uses Npcap.
- Process attribution: psutil socket snapshots → (proto,
  local_port) → (pid, name). Best-effort, documented honestly.
- Geolocation is 100% offline (.mmdb — DB-IP Lite bundles,
  MaxMind GeoLite2 drop-in). Zero outbound calls by design.
- API: FastAPI on 127.0.0.1 only, random per-launch token on
  every endpoint + the WebSocket. No account, no telemetry, AGPL.
- Demo mode (SNITCH_DEMO=1) feeds synthetic traffic through the
  real pipeline — try it without root.
- Fun part: the Windows port wasn't me. Issue #12 has the story —
  bug reports with root-cause analysis, then a stranger sent the
  PRs. I just merged and shipped v1.0.5.

Honest scope note: it visualizes, it does not block — pair it
with OpenSnitch/Portmaster if you want a firewall. Happy to
answer anything, especially parser + privacy architecture.
```

### Règles & légitimité (HN est strict)

- Repost autorisé car le premier est mort à 1 point (guidelines officielles)
- **Jamais** demander d'upvotes, ni cross-poster le lien en disant « allez voter » — HN détecte et shadowban
- Répondre à CHAQUE commentaire dans les minutes qui suivent — la discussion nourrit le ranking
- Si le post décolle : rester en ligne 2-3h, réponses détaillées et honnêtes (les défauts assumés = crédibilité)
- Si ça coule encore : c'est la loterie HN, pas un verdict sur le projet — PH reste l'événement principal

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

## Reddit r/selfhosted (VENDREDI — règle « New Project Friday »)

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
- One-click installers too: Windows .exe, macOS .dmg/.zip,
  Linux AppImage + .deb (Windows port was contributed
  by the community)
- Light/dark theme, EN/FR

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
