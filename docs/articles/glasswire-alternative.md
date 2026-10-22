[English](glasswire-alternative.md) | [Español](glasswire-alternative.es.md) | [Deutsch](glasswire-alternative.de.md) | [Русский](glasswire-alternative.ru.md) | [日本語](glasswire-alternative.ja.md) | [Português](glasswire-alternative.pt-BR.md) | [中文](glasswire-alternative.zh-CN.md)

If you've searched for a network monitor on Windows, you've hit GlassWire. It's polished, it looks great — and then the paywalls start showing up: history behind a subscription, firewall features behind tiers, an account that keeps being suggested, cloud "elite" sync.

There's nothing wrong with paying for software. But "show me what my computer connects to" is basic hygiene — it arguably shouldn't be gated at all. I'm the author of [Snitch](https://github.com/aixisstudio/Snitch), a free, open-source (AGPL) alternative, so let me give you the honest comparison instead of a sales pitch.

## Snitch vs GlassWire, feature by feature

| | **Snitch** | **GlassWire** |
|---|---|---|
| Price | Free, forever | Freemium — key features paywalled |
| License | AGPL open source | Proprietary |
| Account | **None — ever** | Account/cloud tier promoted |
| Telemetry | **No outbound call without opt-in** (GeoIP, updates, threat intel, webhooks all off by default) | Phone-home for sync/features |
| Data location | Local SQLite, yours | Cloud-linked features exist |
| Live world map of connections | ✅ geolocated offline | ✅ (paid tiers) |
| Per-app traffic & bandwidth | ✅ | ✅ (partially free) |
| History | 24h free (SQLite ring buffer) | Limited on free tier |
| Anomaly alerts (port scans, beaconing, exfil, DNS tunneling) | ✅ | ✅ (mostly paid) |
| LAN device scan | ✅ passive, via ARP | ✅ (paid) |
| Firewall / blocking | ✅ OS-firewall orchestration + lockdown (best-effort, needs privileges) | ✅ (GlassWire's firewall is more mature) |
| Threat intel reputation | ✅ opt-in (AbuseIPDB / OTX / VirusTotal, your own key) | ❌ |
| Kill / suspend process | ✅ built-in | ✅ |
| Forensics export | ✅ JSON / CSV / STIX | ❌ |
| Platforms | macOS, Windows, Linux | Windows, Android |
| Privacy score / tracker detection | ✅ editable lists | ❌ |

## Where GlassWire still wins

Being fair:

- **Blocking maturity.** GlassWire's application firewall has had a decade of refinement — Snitch's outbound blocking (added in v1.2) orchestrates the OS-native firewall best-effort and needs capture privileges to actually apply rules. If interactive "deny this app" prompts are your core need, GlassWire (or free Portmaster) is still the more polished choice.
- **Polish.** GlassWire's had a decade of UI work. Snitch is much younger — the graph is great, the settings are functional, expect edges.
- **Long history retention** — Snitch keeps 24h by design (privacy-first means *not* hoarding your traffic either).

## The architecture difference that matters

GlassWire's model is the industry's: free tier → annoyance → subscription → cloud features. Snitch's model is the opposite: the binary you run is the whole product. Nothing to unlock because nothing is locked. Your traffic history lives in a local SQLite file — and the code is AGPL, so it can't quietly start phoning home without the diff being public.

Concretely: API on loopback with token auth, zero telemetry endpoints, no analytics SDK anywhere in the code (you can grep it — it's open source).

## Try it

```bash
# Windows: install Npcap, then run the release exe as Administrator
# Linux/Docker:
docker run --network host ghcr.io/aixisstudio/Snitch
# macOS: packaged app or brew
# Demo mode without admin: SNITCH_DEMO=1
```

Repo: https://github.com/aixisstudio/Snitch — issues and feature requests welcome, the Windows port itself was community-contributed. If it replaces a subscription you didn't want, that's the point. ⭐ if it does.
