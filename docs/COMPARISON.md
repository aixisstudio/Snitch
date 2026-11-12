# Snitch vs Little Snitch vs GlassWire vs Portmaster vs LuLu

**English** | [Français](COMPARISON.fr.md)

An honest, feature-level comparison of the main application firewalls and
connection monitors. We wrote it ourselves, so read it with that bias in mind —
we call out where competitors genuinely win.

## Quick table

| | **Snitch** | **Little Snitch** | **GlassWire** | **Portmaster** | **LuLu** |
|---|---|---|---|---|---|
| License | AGPL-3.0 (FOSS) | Proprietary | Proprietary (freemium) | AGPL-3.0 | GPL-3.0 (FOSS) |
| Price | Free | ~€59 (macOS) | Free + paid tiers | Free (+ paid SPN) | Free / donation |
| Platforms | macOS, Windows, Linux | macOS only | Windows, Android | Windows, macOS, Linux | macOS only |
| Per-app connection view | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ask-on-first-connect prompt | ✅ | ✅ | ✅ | ✅ | ✅ |
| Packet-level inspection | ✅ (own bounded parsers) | ❌ (flows only) | ❌ | Partial (DNS, SNI) | ❌ |
| Passive JA3/JA4 TLS fingerprinting | ✅ | ❌ | ❌ | ❌ | ❌ |
| C2 / threat-intel feeds (ThreatFox…) | ✅ | ❌ | Paid tier | ✅ (filter lists) | ❌ |
| Process context (cmdline, parent) | ✅ | ✅ | ✅ | ✅ | Partial |
| Offline GeoIP map | ✅ | ✅ | ✅ | ❌ | ❌ |
| Scriptable REST/WebSocket API | ✅ | ❌ | ❌ | ✅ (API) | ❌ |
| SIEM export (CEF/ECS/Syslog) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Sends telemetry to vendor | ❌ (local-first) | ❌ | Yes (optional) | Optional | ❌ |
| Requires account | ❌ | ❌ | ❌ | Optional | ❌ |

## Where each one wins

**Little Snitch** — the most polished per-app firewall on macOS, bar none. Deep
rules UI, research assistant, years of refinement. If you want the smoothest
macOS-only experience and don't need source access, packet inspection or an
API, it's the safe pick. Snitch exists because there was no Little Snitch for
Windows/Linux that is also open-source and inspects traffic, not just flows.

**GlassWire** — the prettiest bandwidth/usage graphs on Windows and an easy
mobile companion. Good "what did my PC do yesterday" visualization. It is
closed-source with paid tiers; no packet inspection and less of a privacy
stance.

**Portmaster (Safing)** — the closest philosophical sibling: FOSS, local-first,
great DNS-level filtering with filter lists, and a paid SPN network. Stronger
than Snitch on DNS ad/tracker blocking out of the box; weaker on raw packet
visibility — Snitch shows you the actual bytes (TLS ClientHello, DNS questions,
JA3 fingerprints) and lets you write rules on them.

**LuLu** — the minimalist, free macOS outbound firewall from Objective-See.
Excellent if all you want is "block app X from phoning home" on a Mac with zero
cruft. No inspection, no cross-platform, no API — by design.

**Snitch** — the only one of the five that combines: cross-platform FOSS,
passive TLS fingerprinting (JA3/JA4) for C2 beacon detection, pluggable
threat-intel feeds (ThreatFox/abuse.ch, your own lists), a scriptable
authenticated API, SIEM exports, and per-process context — all local, no
account, no vendor telemetry. The trade-off: the UI is younger than Little
Snitch's, and kernel-level enforcement varies by OS (pf/netsh/nftables under
the hood — see FIREWALL.md for the honest matrix).

## One-line summary

- Need the most polished **macOS-only** firewall → **Little Snitch**
- Need **bandwidth graphs** on Windows → **GlassWire**
- Need **DNS ad/tracker blocking** + optional VPN-like SPN → **Portmaster**
- Need a **minimal free macOS** outbound blocker → **LuLu**
- Need **open, cross-platform, inspectable traffic + C2 detection** → **Snitch**
