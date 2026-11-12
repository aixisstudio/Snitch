# Snitch vs Little Snitch vs GlassWire vs Portmaster vs LuLu

[English](COMPARISON.md) | **Français**

Comparatif honnête, fonctionnalité par fonctionnalité, des principaux pare-feux
applicatifs et moniteurs de connexions. On l'a écrit nous-mêmes — lisez-le avec
ce biais en tête : on dit aussi où les concurrents gagnent réellement.

## Tableau rapide

| | **Snitch** | **Little Snitch** | **GlassWire** | **Portmaster** | **LuLu** |
|---|---|---|---|---|---|
| Licence | AGPL-3.0 (libre) | Propriétaire | Propriétaire (freemium) | AGPL-3.0 | GPL-3.0 (libre) |
| Prix | Gratuit | ~59 € (macOS) | Gratuit + offres payantes | Gratuit (+ SPN payant) | Gratuit / dons |
| Plateformes | macOS, Windows, Linux | macOS uniquement | Windows, Android | Windows, macOS, Linux | macOS uniquement |
| Vue connexions par app | ✅ | ✅ | ✅ | ✅ | ✅ |
| Demande à la 1re connexion | ✅ | ✅ | ✅ | ✅ | ✅ |
| Inspection au niveau paquet | ✅ (parseurs bornés maison) | ❌ (flux seulement) | ❌ | Partiel (DNS, SNI) | ❌ |
| Fingerprinting TLS passif JA3/JA4 | ✅ | ❌ | ❌ | ❌ | ❌ |
| Feeds C2 / threat-intel (ThreatFox…) | ✅ | ❌ | Offre payante | ✅ (listes de filtres) | ❌ |
| Contexte processus (cmdline, parent) | ✅ | ✅ | ✅ | ✅ | Partiel |
| Carte GeoIP hors-ligne | ✅ | ✅ | ✅ | ❌ | ❌ |
| API REST/WebSocket scriptable | ✅ | ❌ | ❌ | ✅ (API) | ❌ |
| Export SIEM (CEF/ECS/Syslog) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Télémétrie vers l'éditeur | ❌ (local-first) | ❌ | Oui (optionnelle) | Optionnelle | ❌ |
| Compte requis | ❌ | ❌ | ❌ | Optionnel | ❌ |

## Où chacun gagne

**Little Snitch** — le pare-feu par app le plus abouti sur macOS, sans conteste.
UI de règles très travaillée, assistant de recherche, des années de raffinement.
Si vous voulez l'expérience macOS la plus lisse et n'avez pas besoin du code
source, de l'inspection de paquets ni d'une API, c'est le choix sûr. Snitch
existe parce qu'il n'y avait pas de Little Snitch pour Windows/Linux qui soit
aussi open-source et qui inspecte le trafic, pas seulement les flux.

**GlassWire** — les plus beaux graphiques de bande passante sur Windows et un
compagnon mobile pratique. Bonne visualisation « qu'a fait mon PC hier ». C'est
du closed-source avec des paliers payants ; pas d'inspection de paquets et une
posture vie privée moindre.

**Portmaster (Safing)** — le frère philosophique le plus proche : libre,
local-first, excellent filtrage DNS avec listes de filtres, et un réseau SPN
payant. Plus fort que Snitch sur le blocage pubs/trackers DNS clé en main ;
plus faible sur la visibilité paquet — Snitch montre les octets réels
(ClientHello TLS, requêtes DNS, empreintes JA3) et permet d'écrire des règles
dessus.

**LuLu** — le pare-feu sortant macOS minimaliste et gratuit d'Objective-See.
Excellent si vous voulez juste « bloquer l'app X qui téléphone à la maison »
sur Mac sans superflu. Pas d'inspection, pas de multi-plateforme, pas d'API —
par design.

**Snitch** — le seul des cinq qui combine : multi-plateforme et libre,
fingerprinting TLS passif (JA3/JA4) pour détecter les balises C2, feeds
threat-intel enfichables (ThreatFox/abuse.ch, vos propres listes), une API
authentifiée scriptable, des exports SIEM et du contexte par processus — tout
en local, sans compte, sans télémétrie. Contrepartie : l'UI est plus jeune que
celle de Little Snitch, et l'enforcement au niveau noyau varie selon l'OS
(pf/netsh/nftables sous le capot — voir FIREWALL.md pour la matrice honnête).

## Résumé en une ligne

- Le pare-feu **macOS** le plus abouti → **Little Snitch**
- Des **graphes de bande passante** sous Windows → **GlassWire**
- Du **blocage DNS pubs/trackers** + SPN type VPN → **Portmaster**
- Un **bloqueur sortant macOS minimal** et gratuit → **LuLu**
- Un trafic **open, multi-plateforme, inspectable + détection C2** → **Snitch**
