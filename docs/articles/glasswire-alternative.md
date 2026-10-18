If you've searched for a network monitor on Windows, you've hit GlassWire. It's polished, it looks great — and then the paywalls start showing up: history behind a subscription, firewall features behind tiers, an account that keeps being suggested, cloud "elite" sync.

There's nothing wrong with paying for software. But "show me what my computer connects to" is basic hygiene — it arguably shouldn't be gated at all. I'm the author of [Snitch](https://github.com/aixisstudio/Snitch), a free, open-source (AGPL) alternative, so let me give you the honest comparison instead of a sales pitch.

## Snitch vs GlassWire, feature by feature

| | **Snitch** | **GlassWire** |
|---|---|---|
| Price | Free, forever | Freemium — key features paywalled |
| License | AGPL open source | Proprietary |
| Account | **None — ever** | Account/cloud tier promoted |
| Telemetry | **Zero outbound calls** (GeoIP download is opt-in) | Phone-home for sync/features |
| Data location | Local SQLite, yours | Cloud-linked features exist |
| Live world map of connections | ✅ geolocated offline | ✅ (paid tiers) |
| Per-app traffic & bandwidth | ✅ | ✅ (partially free) |
| History | 24h free (SQLite ring buffer) | Limited on free tier |
| Anomaly alerts (port scans, beaconing, exfil) | ✅ | ✅ (mostly paid) |
| LAN device scan | ✅ passive, via ARP | ✅ (paid) |
| Firewall / blocking | ❌ visualizer only | ✅ (this is GlassWire's real strength) |
| Platforms | macOS, Windows, Linux | Windows, Android |
| Privacy score / tracker detection | ✅ editable lists | ❌ |

## Where GlassWire still wins

Being fair:

- **Blocking.** GlassWire has a real application firewall. Snitch deliberately doesn't block — it shows you, it doesn't decide. If "deny this app" is your core need, GlassWire (or free Portmaster) is the right tool.
- **Polish.** GlassWire's had a decade of UI work. Snitch is 3 weeks old — the graph is great, the settings are functional, expect edges.
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
