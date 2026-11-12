# Product Hunt Launch Kit — Snitch

## Timing
Launch Tuesday–Thursday, 00:01–00:05 PST to get full 24h on the daily leaderboard.
Post as "maker" from the aixisstudio PH account; have the GitHub repo + demo GIF ready.

## Tagline (60 chars max)
Open-source Little Snitch alternative that sees malware, not just traffic

## Description (260 chars max)
Snitch is a free, local-first firewall & network monitor for macOS, Windows and Linux. It watches every connection per process, fingerprints TLS handshakes (JA3/JA4) to catch C2 beacons, maps hosts offline — no account, no cloud, no telemetry. AGPL-3.0.

## Topics / categories
Open Source, Security, Privacy, Developer Tools, Cybersecurity

## First comment (maker comment, post immediately after launch)
Hi PH! Snitch started as "Little Snitch for Windows/Linux that doesn't call home". It's fully local-first: own bounded packet parsers (no Scapy — licence clash), offline GeoIP, authenticated loopback-only API. v1.6.5 adds passive JA3/JA4 TLS fingerprinting + ThreatFox C2 feeds — it can smell known malware families without decrypting a byte. Honest limitation: enforcement depth varies per OS (pf/netsh/nftables) — the matrix is in the docs. Demo mode needs no root: `snitch --demo`. AMA — happy to answer about packet parsing, JA3 internals, or going AGPL.

## Gallery assets (prepare before launch)
1. docs/assets/demo.gif — live graph (already in repo)
2. Screenshot: Firewall rules UI with ja3/ja4 fields
3. Screenshot: offline map with geolocated hosts + alert card
4. Screenshot: THREAT_HIT alert on a JA3 match
5. 240x240 app icon (docs/assets/icon.png or generate)

## Link
https://github.com/aixisstudio/Snitch
