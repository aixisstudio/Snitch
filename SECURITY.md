# Security Policy / Politique de sécurité

## Reporting / Signalement

**EN:** Please report vulnerabilities privately via GitHub's "Report a
vulnerability" feature (Security tab) or by emailing the maintainers listed
in the repository profile. Do not open public issues for security problems.

**FR :** Signalez les vulnérabilités en privé via la fonction « Report a
vulnerability » de GitHub (onglet Security) ou par email aux mainteneurs.
N'ouvrez pas d'issue publique pour les problèmes de sécurité.

## Local attack surface / Surface d'attaque locale

**EN:** The API exposes your full traffic graph — it is protected by design:

- **Token auth** on every REST endpoint and the WebSocket
  (`X-Snitch-Token` or `?token=`). Generated per launch under Electron,
  persisted 0600 otherwise.
- **Loopback bind** (`127.0.0.1`) in all modes by default.
- **Origin allowlist** on the WebSocket handshake (loopback hosts + `null`)
  to block cross-site WebSocket hijacking.
- **Restricted CORS** — loopback origins only, no credentials.

**FR :** L'API expose tout votre graphe de trafic — elle est protégée par
conception :

- **Authentification par jeton** sur chaque endpoint REST et le WebSocket
  (`X-Snitch-Token` ou `?token=`). Généré à chaque lancement sous Electron,
  persisté en 0600 sinon.
- **Bind loopback** (`127.0.0.1`) par défaut dans tous les modes.
- **Liste blanche d'Origin** sur le handshake WebSocket (hôtes loopback +
  `null`) pour bloquer le détournement de WebSocket cross-site.
- **CORS restreint** — origines loopback uniquement, sans identifiants.

## Privileges / Privilèges

**EN:** Packet capture requires elevated privileges — but only the backend
holds them. The packaged Electron app runs the UI unprivileged on every OS
and elevates ONLY the backend through the platform's native prompt:

- **Windows:** `Start-Process -Verb RunAs` (one UAC prompt per launch) + Npcap (installed by you from npcap.com)
- **macOS:** `osascript … with administrator privileges` (native password dialog)
- **Linux:** `pkexec` (polkit dialog); falls back to unprivileged if polkit is absent

The elevated child is stopped through the authenticated `/shutdown` endpoint
since an unprivileged process cannot signal it. Declining the prompt offers
retry / continue-without-capture instead of a hard quit.

**FR :** La capture de paquets exige des privilèges élevés — mais seul le
backend les détient. L'app Electron packagée fait tourner l'UI sans
privilèges sur tous les OS et n'élève QUE le backend via l'invite native de
la plateforme :

- **Windows :** `Start-Process -Verb RunAs` (une invite UAC par lancement) + Npcap (installé par vos soins depuis npcap.com)
- **macOS :** `osascript … with administrator privileges` (dialogue mot de passe natif)
- **Linux :** `pkexec` (dialogue polkit) ; repli non privilégié si polkit est absent

L'enfant élevé est arrêté via l'endpoint authentifié `/shutdown` puisqu'un
processus non privilégié ne peut pas le signaler. Refuser l'invite propose
réessayer / continuer sans capture au lieu d'une sortie brutale.

## Dependencies / Dépendances

**EN:** Scapy was removed (GPL-2.0-only + large attack surface). Capture is a
minimal ctypes binding to libpcap plus our own bounded parser. Dependencies
are pinned and scanned by Dependabot.

**FR :** Scapy a été retiré (GPL-2.0-only + large surface d'attaque). La
capture est un binding ctypes minimal vers libpcap plus notre propre parseur
borné. Les dépendances sont épinglées et surveillées par Dependabot.
