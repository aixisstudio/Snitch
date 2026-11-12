---
title: "Teaching an open-source firewall to smell C2 beacons: passive JA3/JA4 fingerprinting in pure Python"
published: true
tags: security, python, opensource, networking
---

Most app firewalls tell you *which process* opened a connection. That's useful — but the interesting question for defenders is different: **does this TLS handshake look like a known malware family?**

We just shipped that in Snitch v1.6.5 — and it required zero decryption, zero cloud calls, and no heavyweight dependencies.

## The idea in 60 seconds

Every TLS client announces itself in the first packet: the ClientHello carries the TLS version, the cipher suite list, extensions, supported curves and point formats — in a specific order. Hash that tuple and you get a **JA3** fingerprint (MD5) or a **JA4** fingerprint (FoxIO's newer format) — a stable signature of *the TLS stack doing the talking*.

Cobalt Strike's beacon, Sliver, Mythic — they don't look like Chrome or curl at the ClientHello level. Their cipher ordering and extension sets are fingerprints known from public OSINT. Same malware, different IP? The JA3 still matches.

## The parser: bounded, passive, no dependencies

Snitch ships its own bounded packet parsers (we dropped Scapy early on — GPL-2.0-only doesn't mix with AGPL shipping). The ClientHello parser is ~150 lines of `struct` unpacking:

```python
def parse_tls_client_hello(payload):
    if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
        return None, None, None          # not a TLS handshake record
    hs = 5
    if payload[hs] != 0x01:
        return None, None, None          # not a ClientHello
    # ... walk version, random, session ID, cipher suites
    ciphers = [c for c in raw_ciphers if not _is_grease(c)]
    # JA3: version,ciphers,extensions,curves,point_formats → MD5
    ja3_hash = md5(ja3_string.encode()).hexdigest()
```

Two details that matter:

**GREASE filtering.** Modern TLS stacks inject random "GREASE" values (RFC 8701, the `0x?a?a` pattern) to keep middleboxes honest. If you hash them raw, Chrome produces a *different JA3 on every connection*. The check is one bitmask:

```python
def _is_grease(val):
    return (val & 0x0F0F) == 0x0A0A and ((val >> 8) & 0xFF) == (val & 0xFF)
```

**Bounded execution.** Every loop is capped by actual buffer length — a malformed ClientHello can never make the parser read past the packet. When you're parsing hostile traffic, your parser is your attack surface.

## The detection side: local lookup, honest data

Fingerprints land on the parsed packet and flow through the same pipeline as everything else — meaning you can write an alert rule on `ja3` / `ja4` fields directly, or let the bundled `c2_fingerprints.json` flag known C2 families automatically.

One thing we got bitten by during review: the first version of that JSON contained *fabricated* JA4 values — plausible-looking placeholder hashes that would never match real traffic. We caught it in review and shipped only fingerprints with verifiable OSINT provenance (Fox-IT, abuse.ch, JPCERT/CC, Unit42 write-ups). Where no published JA4 existed, the field is `null`. A security tool that ships synthetic indicators is worse than a tool that ships none.

## Try it

```
pip install snitch  # or scoop install extras/snitch on Windows
snitch --demo       # synthetic traffic, no root needed
```

Then watch the live graph flag a `THREAT_HIT` alert when a fingerprint matches. Everything runs on loopback — the API is authenticated and nothing leaves your machine.

Repo: https://github.com/aixisstudio/Snitch — AGPL-3.0, macOS/Windows/Linux. Contributions welcome; the JA3/JA4 work came from an external contributor and it shows in the quality.
