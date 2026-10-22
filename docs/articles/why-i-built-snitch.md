[English](why-i-built-snitch.md) | [Español](why-i-built-snitch.es.md) | [Deutsch](why-i-built-snitch.de.md) | [Русский](why-i-built-snitch.ru.md) | [日本語](why-i-built-snitch.ja.md) | [Português](why-i-built-snitch.pt-BR.md) | [中文](why-i-built-snitch.zh-CN.md)

Three weeks ago I wanted to answer a stupidly simple question: **who is my computer talking to?**

Not "can I capture packets" (Wireshark can, and it's a microscope when I wanted a windshield). Not "block connections" (Little Snitch does that on macOS, $59, and nothing equivalent exists on Windows). Just: a live, visual answer. Which app, which server, which country — right now.

So I built [Snitch](https://github.com/aixisstudio/Snitch). Open source, AGPL, UI in 8 languages, ~400 stars in three weeks. Here's what I learned — and the part where strangers wrote my Windows port for me.

## The build

The constraint I set myself: **no heavy dependencies, no telemetry, ever.** 

- Capture: `ctypes → libpcap` on macOS/Linux, Npcap on Windows. No Scapy — direct bindings are lighter and give exact field control.
- Parsing: hand-rolled IPv4/IPv6/TCP/UDP/DNS/TLS-SNI decoders. ~2K lines for the entire pipeline.
- Backend: FastAPI + WebSockets + a SQLite ring buffer (24h retention, then it deletes itself — privacy means *not* hoarding either).
- Frontend: React + D3 force graph + TopoJSON world map.
- Geolocation: local MaxMind/DB-IP file. IPs never leave the machine.

Security posture as a feature: API on loopback only, token-authenticated, and every outbound call is opt-in — GeoIP download, update checks, threat-intel lookups and webhooks are all off by default. For a privacy tool, the code *is* the promise — AGPL makes it auditable.

## The thing I didn't plan

I shipped macOS first and tagged the repo "help wanted" on Windows. Within days:

- Users filed bug reports with **root-cause analysis included** — not "it doesn't work", actual stack traces and the faulty capture path identified
- A stranger I'd never spoken to sent three PRs: Npcap capture, network interface selection, a startup crash
- Someone else opened the [winget package PR](https://github.com/microsoft/winget-pkgs/pull/455520)

v1.0.5 shipped last week with the Windows port fully working. The most powerful distribution channel this project found wasn't a marketing trick — it was "put a real problem in public, and people who have the same problem show up".

## What the traffic data said

Fun meta-moment: Snitch's own referral traffic told the story. A Chinese tech newsletter (ruanyifeng.com) featured the project — suddenly ~20% of traffic was Chinese readers staring at an English README. So now there's a full [中文 README](https://github.com/aixisstudio/Snitch/blob/main/README.zh-CN.md). The data decides; I just listen.

## What I'd tell anyone building dev tools

1. **Solve a felt problem.** "Who is my machine talking to" is visceral — everyone wonders, nobody can see it.
2. **Local-first is a differentiator now.** "No account, no telemetry" isn't a limitation, it's the pitch.
3. **Bilingual/multi-language docs aren't charity** — they're distribution to audiences with zero competition.
4. **Issues and Discussions convert.** Fast answers turned bug reporters into contributors. That's how my Windows port happened.

## Try it

```bash
docker run --network host ghcr.io/aixisstudio/snitch   # Linux
# macOS/Windows: releases page — SNITCH_DEMO=1 runs it without admin
```

Repo: https://github.com/aixisstudio/Snitch — AGPL, UI + docs in EN/FR/ES/DE/RU/JA/PT-BR/中文, and v1.2 added the thing people asked for most: outbound blocking via the OS firewall, plus opt-in threat intel and a one-click forensics export. The ["what did you catch?" thread](https://github.com/aixisstudio/Snitch/discussions/39) is open, and a ⭐ genuinely helps if it earns it.
