# Security Policy / Politique de sécurité

## Reporting / Signalement

**EN:** Please report vulnerabilities privately via GitHub's "Report a
vulnerability" feature (Security tab) or by emailing the maintainers listed
in the repository profile. Do not open public issues for security problems.

**FR :** Signalez les vulnérabilités en privé via la fonction « Report a
vulnerability » de GitHub (onglet Security) ou par email aux mainteneurs.
N'ouvrez pas d'issue publique pour les problèmes de sécurité.

## Local attack surface / Surface d'attaque locale

The API exposes your full traffic graph — it is protected by design:

- **Token auth** on every REST endpoint and the WebSocket
  (`X-Snitch-Token` or `?token=`). Generated per launch under Electron,
  persisted 0600 otherwise.
- **Loopback bind** (`127.0.0.1`) in all modes by default.
- **Origin allowlist** on the WebSocket handshake (loopback hosts + `null`)
  to block cross-site WebSocket hijacking.
- **Restricted CORS** — loopback origins only, no credentials.

## Privileges / Privilèges

Packet capture requires elevated privileges. Current limitation: under
Electron the **whole app** (Chromium UI included) runs elevated on Windows
(`requireAdministrator`). A privileged-daemon split (unprivileged UI +
elevated capture backend) is a known roadmap item — see issues.

- Windows: Administrator + Npcap (installed by you from npcap.com)
- Linux: `setcap cap_net_raw,cap_net_admin` on the binary, or root
- macOS: read access to `/dev/bpf*` (experimental support)

## Dependencies / Dépendances

Scapy was removed (GPL-2.0-only + large attack surface). Capture is a minimal
ctypes binding to libpcap plus our own bounded parser. Dependencies are
pinned and scanned by Dependabot.
