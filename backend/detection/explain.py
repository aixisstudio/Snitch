"""
EN: Alert explainability — deterministic, rule-based explanations for every
    alert type the detector can emit. This is deliberately NOT a language
    model: each template is hand-written, bilingual, and bounded — the
    honest version of "explain this alert" that works offline, costs zero
    resources, and can never hallucinate. A local SLM stays on the research
    roadmap; this is what ships today.

    Served by GET /security/explain?type=<ALERT_TYPE> — the frontend uses
    it for the "Why am I seeing this?" affordance on alert cards.

FR: Explicabilité des alertes — explications déterministes par règles pour
    chaque type d'alerte du détecteur. Ce n'est volontairement PAS un modèle
    de langage : chaque gabarit est écrit à la main, bilingue et borné — la
    version honnête de « explique cette alerte » qui marche hors-ligne, ne
    coûte rien et ne peut pas halluciner. Un SLM local reste à la roadmap ;
    voici ce qui est livré aujourd'hui.
"""

from __future__ import annotations


def _e(title_en, title_fr, what_en, what_fr, why_en, why_fr,
       actions_en, actions_fr) -> dict:
    """EN: One explanation record — bilingual fields, parallel action lists.
    FR: Une explication — champs bilingues, listes d'actions parallèles."""
    return {
        "title_en": title_en, "title_fr": title_fr,
        "what_en": what_en, "what_fr": what_fr,
        "why_en": why_en, "why_fr": why_fr,
        "actions_en": actions_en, "actions_fr": actions_fr,
    }


EXPLANATIONS: dict[str, dict] = {

"NEW_HOST": _e(
    "First contact with a remote host",
    "Premier contact avec un hôte distant",
    "Snitch saw traffic to an IP it had never observed since the session started.",
    "Snitch a vu du trafic vers une IP jamais observée depuis le début de la session.",
    "Mostly informational — every new server you legitimately visit triggers it. "
    "It becomes meaningful when paired with other alerts or an unexpected process.",
    "Surtout informatif — tout nouveau serveur légitime la déclenche. Elle prend "
    "du sens combinée à d'autres alertes ou à un processus inattendu.",
    ["Check which process opened the connection",
     "Look at the geolocation and resolved domain",
     "If unexpected, check its reputation (Threat intel)"],
    ["Identifier le processus à l'origine de la connexion",
     "Regarder la géolocalisation et le domaine résolu",
     "Si inattendu, vérifier sa réputation (threat intel)"]),

"NEW_LAN_DEVICE": _e(
    "New device joined the LAN",
    "Nouvel appareil sur le LAN",
    "A MAC/IP pair appeared in the ARP table that Snitch had not seen.",
    "Un couple MAC/IP est apparu dans la table ARP, inconnu de Snitch.",
    "Phones, TVs and guests legitimately join networks — but on a network you "
    "control, an unknown device deserves one look.",
    "Téléphones, TV et invités rejoignent légitimement le réseau — mais sur un "
    "réseau que vous contrôlez, un appareil inconnu mérite un œil.",
    ["Compare with devices you own (hostname, MAC vendor)",
     "If unknown, check your router's client list"],
    ["Comparer avec vos appareils (nom d'hôte, fabricant MAC)",
     "Si inconnu, vérifier la liste des clients du routeur"]),

"DEVICE_OFFLINE": _e(
    "A LAN device went silent",
    "Un appareil LAN s'est tu",
    "A previously-seen LAN device disappeared from the ARP table.",
    "Un appareil LAN connu a disparu de la table ARP.",
    "Usually a phone sleeping or a laptop leaving. Relevant only for devices "
    "expected to stay (servers, NAS).",
    "Généralement un téléphone en veille ou un portable qui part. Pertinent "
    "seulement pour les appareils censés rester (serveurs, NAS).",
    ["None needed for mobile devices",
     "For infrastructure, check power/network state"],
    ["Rien à faire pour les mobiles",
     "Pour l'infrastructure, vérifier alimentation et réseau"]),

"PORT_SCAN": _e(
    "Port scan pattern",
    "Motif de scan de ports",
    "One host touched many distinct ports in a short window — the signature of "
    "reconnaissance (nmap-style).",
    "Un hôte a touché de nombreux ports distincts en peu de temps — signature "
    "de reconnaissance (style nmap).",
    "Scans precede attacks. Local scanners are sometimes legit (admin tools) — "
    "remote scanners are not.",
    "Les scans précèdent les attaques. Un scanner local peut être légitime "
    "(outils d'admin) — un scanner distant ne l'est pas.",
    ["Identify the scanning process / host",
     "Block the source IP with a firewall rule",
     "Kill the process if it is local and unknown"],
    ["Identifier le processus / l'hôte qui scanne",
     "Bloquer l'IP source avec une règle pare-feu",
     "Tuer le processus s'il est local et inconnu"]),

"BEACON": _e(
    "Regular-interval connections (beaconing)",
    "Connexions à intervalle régulier (balisage)",
    "Outbound connections to one host at near-constant intervals — the heartbeat "
    "pattern of malware calling its C2.",
    "Connexions sortantes vers un même hôte à intervalles quasi constants — le "
    "pouls typique d'un malware qui appelle son C2.",
    "Legit software also polls (sync, telemetry) — jitter and payload size help "
    "tell them apart: malware beacons are usually tiny and very regular.",
    "Les logiciels légitimes interrogent aussi (sync, télémétrie) — jitter et "
    "taille des paquets aident à distinguer : les beacons sont petits et très réguliers.",
    ["Check the process behind the connections",
     "Compare interval and byte counts with known sync services",
     "Run a threat-intel check on the destination",
     "Consider a firewall rule if unexplained"],
    ["Identifier le processus derrière les connexions",
     "Comparer intervalle et volume avec des services de sync connus",
     "Lancer une vérif threat-intel sur la destination",
     "Envisager une règle pare-feu si inexpliqué"]),

"VOLUME_SPIKE": _e(
    "Traffic volume spike",
    "Pic de volume de trafic",
    "Bytes-per-second to or from a host jumped far above its rolling baseline.",
    "Le débit vers/depuis un hôte a bondi bien au-dessus de sa moyenne mobile.",
    "Bulk transfers are legit (backup, video, updates) — an unexplained burst "
    "to an unknown host is not.",
    "Les gros transferts sont légitimes (backup, vidéo, mises à jour) — un pic "
    "inexpliqué vers un hôte inconnu ne l'est pas.",
    ["Check what the process was doing at that moment",
     "Export forensics for the process if unexplained"],
    ["Vérifier ce que faisait le processus à cet instant",
     "Exporter le forensique du processus si inexpliqué"]),

"MEDIA_EXFIL": _e(
    "Upload while camera/mic active",
    "Envoi de données pendant caméra/micro actifs",
    "Outbound traffic coincided with an active microphone or camera — the "
    "classic spyware pattern of streaming your sensors out.",
    "Du trafic sortant a coïncidé avec un micro ou une caméra actifs — le motif "
    "classique d'un spyware qui exfiltre vos capteurs.",
    "Video calls legitimately do this — the alert matters when the uploading "
    "process is NOT your call app.",
    "Les visioconférences font légitimement cela — l'alerte compte quand le "
    "processus émetteur n'est PAS votre app d'appel.",
    ["Verify which app holds the camera/mic",
     "Check that the uploader is the same application",
     "Kill + block if the process is unknown"],
    ["Vérifier quelle app détient caméra/micro",
     "Vérifier que l'émetteur est la même application",
     "Tuer + bloquer si le processus est inconnu"]),

"UPLOAD_SPIKE": _e(
    "Abnormal outbound volume for a process",
    "Volume sortant anormal pour un processus",
    "A process sent more data than its configured threshold allows — possible "
    "data exfiltration.",
    "Un processus a envoyé plus de données que le seuil configuré — "
    "exfiltration possible.",
    "Cloud sync and backups send a lot — the question is whether THIS process "
    "should be uploading at all.",
    "La sync cloud et les backups envoient beaucoup — la question est de savoir "
    "si CE processus devrait envoyer quoi que ce soit.",
    ["Look at the destination — cloud provider or unknown host?",
     "Adjust the threshold in Settings if this is expected",
     "Export the process bundle (SHA-256, parent tree)"],
    ["Regarder la destination — cloud connu ou hôte inconnu ?",
     "Ajuster le seuil dans Réglages si c'est attendu",
     "Exporter le paquet forensique (SHA-256, arbre parent)"]),

"WATCHLIST_HIT": _e(
    "Watched IP/domain contacted",
    "IP/domaine surveillé contacté",
    "Traffic matched an entry on your personal watchlist.",
    "Le trafic correspond à une entrée de votre liste de surveillance.",
    "You pinned this — either a host you don't trust or one you want visibility on.",
    "Vous l'avez épinglé — soit un hôte auquel vous ne faites pas confiance, "
    "soit un hôte que vous voulez suivre.",
    ["Review why it was watched",
     "Block it with a firewall rule if unwanted"],
    ["Revoir pourquoi il était surveillé",
     "Le bloquer via une règle pare-feu si indésirable"]),

"SUSPICIOUS_PROCESS": _e(
    "Unusual process networking",
    "Activité réseau inhabituelle d'un processus",
    "A process with no network business opened connections (e.g. a calculator, "
    "notepad-class tool).",
    "Un processus sans vocation réseau a ouvert des connexions (calculatrice, "
    "bloc-notes…).",
    "Offline tools going online is a top infection indicator — legit updates "
    "are the main false positive.",
    "Un outil hors-ligne qui se connecte est un indicateur majeur d'infection — "
    "les mises à jour légitimes sont le principal faux positif.",
    ["Check the executable path — is it the real tool?",
     "Run integrity check on the process",
     "Kill and block if unexplained"],
    ["Vérifier le chemin de l'exécutable — est-ce le vrai outil ?",
     "Lancer un contrôle d'intégrité sur le processus",
     "Tuer et bloquer si inexpliqué"]),

"SUSPICIOUS_PORT": _e(
    "Connection on an unusual port",
    "Connexion sur un port inhabituel",
    "A flow used a port that does not match its apparent purpose — e.g. "
    "non-HTTP traffic on 443, or a service port rarely seen outbound.",
    "Un flux utilise un port qui ne correspond pas à son usage apparent — ex. "
    "du non-HTTP sur 443, ou un port rarement vu en sortie.",
    "Attackers hide tunnels on common-looking ports; protocol/port mismatch is "
    "the cheapest way to spot them.",
    "Les attaquants cachent des tunnels sur des ports banals ; le mismatch "
    "protocole/port est le moyen le plus simple de les repérer.",
    ["Look at the actual payload classification",
     "Check if the process is expected to use that port",
     "Consider blocking the port for that process"],
    ["Regarder la classification réelle du trafic",
     "Vérifier que le processus utilise normalement ce port",
     "Envisager de bloquer le port pour ce processus"]),

"DNS_TUNNEL": _e(
    "Possible DNS tunnelling",
    "Tunnel DNS possible",
    "DNS queries with oversized names/labels or unusual frequency — the standard "
    "exfiltration channel that bypasses most firewalls.",
    "Requêtes DNS avec noms/labels surdimensionnés ou fréquence anormale — le "
    "canal d'exfiltration classique qui contourne la plupart des pare-feux.",
    "DNS is allowed almost everywhere, so malware encodes data in subdomains. "
    "Long random-looking labels are the tell.",
    "Le DNS est autorisé presque partout, donc les malwares encodent les données "
    "en sous-domaines. Les labels longs et aléatoires sont le signal.",
    ["Identify the querying process",
     "Inspect the queried domain",
     "Block the process or the resolver if confirmed"],
    ["Identifier le processus qui interroge",
     "Inspecter le domaine interrogé",
     "Bloquer le processus ou le résolveur si confirmé"]),

"CLEARTEXT": _e(
    "Unencrypted protocol in use",
    "Protocole non chiffré utilisé",
    "Outbound traffic on a legacy plaintext port (FTP, Telnet, HTTP, plain "
    "mail) — credentials or content readable on the wire.",
    "Trafic sortant sur un port en clair historique (FTP, Telnet, HTTP, mail "
    "non chiffré) — identifiants ou contenu lisibles sur le réseau.",
    "Anything readable on the wire can be stolen or tampered — on public Wi-Fi "
    "especially.",
    "Tout ce qui est lisible sur le réseau peut être volé ou altéré — sur Wi-Fi "
    "public surtout.",
    ["Check whether an encrypted alternative exists (HTTPS, SFTP, SSH)",
     "Avoid credentials over this connection",
     "Pin a note via the watchlist if it must stay"],
    ["Vérifier qu'une alternative chiffrée existe (HTTPS, SFTP, SSH)",
     "Éviter les identifiants sur cette connexion",
     "Épingler via la watchlist si elle doit rester"]),

"BASELINE_DEVIATION": _e(
    "Process changed its network habits",
    "Le processus a changé d'habitudes réseau",
    "A known process contacted a country or pattern outside its learned "
    "profile — Snitch's per-app baseline flags the drift.",
    "Un processus connu a contacté un pays ou un motif hors de son profil "
    "appris — la baseline par app de Snitch signale la dérive.",
    "Updates change destinations legitimately — but a chat app suddenly "
    "reaching an unusual country deserves a look.",
    "Les mises à jour changent légitimement de destination — mais une app de "
    "chat qui contacte soudain un pays inhabituel mérite un œil.",
    ["Check if the app recently updated",
     "Run integrity check on the executable",
     "Reset its baseline if the new behaviour is intended"],
    ["Vérifier si l'app a récemment été mise à jour",
     "Lancer un contrôle d'intégrité de l'exécutable",
     "Réinitialiser sa baseline si le comportement est voulu"]),

"THREAT_HIT": _e(
    "Threat-intel flagged destination",
    "Destination signalée par la threat intel",
    "The configured reputation provider (AbuseIPDB/OTX/VirusTotal — your own "
    "key, opt-in) reports this IP as suspicious or malicious.",
    "Le fournisseur de réputation configuré (AbuseIPDB/OTX/VirusTotal — votre "
    "clé, opt-in) rapporte cette IP comme suspecte ou malveillante.",
    "Reputation feeds are not perfect, but a flagged C2/proxy/botnet host "
    "merits immediate review.",
    "Les flux de réputation ne sont pas parfaits, mais un hôte signalé "
    "C2/proxy/botnet mérite une revue immédiate.",
    ["Read the provider detail in the alert",
     "Block the IP with a firewall rule",
     "Export forensics for the connecting process"],
    ["Lire le détail du fournisseur dans l'alerte",
     "Bloquer l'IP via une règle pare-feu",
     "Exporter le forensique du processus connecté"]),

"BLOCKED_ATTEMPT": _e(
    "Firewall rule matched a packet",
    "Une règle pare-feu a matché un paquet",
    "Traffic matching an active firewall rule (or lockdown) was observed — "
    "with privileges the OS also dropped it.",
    "Du trafic correspondant à une règle pare-feu active (ou au lockdown) a "
    "été observé — avec privilèges, l'OS l'a aussi droppé.",
    "Confirms the policy works; repeated attempts from a blocked process are "
    "the interesting signal.",
    "Confirme que la politique fonctionne ; les tentatives répétées d'un "
    "processus bloqué sont le signal intéressant.",
    ["Watch the attempt counter on the rule",
     "Investigate the blocked process if it insists",
     "Tune or delete the rule if it is wrong"],
    ["Surveiller le compteur de tentatives de la règle",
     "Investiguer le processus bloqué s'il insiste",
     "Ajuster ou supprimer la règle si elle est fausse"]),

"LOCKDOWN": _e(
    "Lockdown mode enabled",
    "Mode lockdown activé",
    "The panic switch is on — outbound traffic to public IPs is dropped; "
    "loopback and LAN stay alive.",
    "Le bouton panique est actif — le trafic sortant vers les IP publiques est "
    "coupé ; loopback et LAN restent vivants.",
    "Use during an active incident to freeze exfiltration while you investigate.",
    "À utiliser pendant un incident pour figer toute exfiltration le temps "
    "d'investiguer.",
    ["Investigate flagged processes while isolated",
     "Disable when the incident is resolved"],
    ["Investiguer les processus signalés pendant l'isolement",
     "Désactiver quand l'incident est résolu"]),

"BINARY_CHANGED": _e(
    "Executable modified on disk",
    "Exécutable modifié sur disque",
    "The SHA-256 of a running process's executable no longer matches the hash "
    "recorded for that path — the file was replaced or patched.",
    "Le SHA-256 de l'exécutable d'un processus actif ne correspond plus au hash "
    "enregistré pour ce chemin — le fichier a été remplacé ou patché.",
    "Legit updates replace binaries — but an unexplained change under a "
    "running PID is a tampering indicator.",
    "Les mises à jour remplacent légitimement les binaires — mais un changement "
    "inexpliqué sous un PID actif indique une altération.",
    ["Compare with the app's update timeline",
     "Export forensics (parent tree, hash) now",
     "Kill + block if the change is unexplained"],
    ["Comparer avec l'historique de mises à jour de l'app",
     "Exporter le forensique (arbre parent, hash) immédiatement",
     "Tuer + bloquer si le changement est inexpliqué"]),

"NAME_MISMATCH": _e(
    "Process name/executable mismatch",
    "Mismatch nom/exécutable du processus",
    "The process's reported name does not match its executable's basename — "
    "classic masquerading (malware named 'svchost' living outside System32).",
    "Le nom rapporté du processus ne correspond pas au basename de son "
    "exécutable — masquage classique (malware nommé « svchost » hors System32).",
    "Renamed copies and launchers cause rare false positives — location and "
    "parent process tell the truth.",
    "Les copies renommées et launchers causent de rares faux positifs — "
    "l'emplacement et le processus parent disent la vérité.",
    ["Check the executable's path",
     "Export the process bundle to see the parent chain",
     "Kill + block if the binary is unexpected"],
    ["Vérifier le chemin de l'exécutable",
     "Exporter le paquet pour voir la chaîne parente",
     "Tuer + bloquer si le binaire est inattendu"]),

"MEM_RWX": _e(
    "Executable-writable memory region",
    "Région mémoire exécutable-inscriptible",
    "The process maps memory that is simultaneously writable and executable "
    "(rwxp) — the signature of injected shellcode or reflective loading. "
    "Linux only (/proc/pid/maps).",
    "Le processus mappe de la mémoire à la fois inscriptible et exécutable "
    "(rwxp) — signature de shellcode injecté ou de chargement réflexif. "
    "Linux uniquement (/proc/pid/maps).",
    "JIT engines (browsers, node, java) legitimately use RWX pages — reported "
    "at info level for those. For any other process it is a strong anomaly.",
    "Les moteurs JIT (navigateurs, node, java) utilisent légitimement des pages "
    "RWX — signalés en info pour ceux-là. Pour tout autre processus, c'est une "
    "anomalie forte.",
    ["Check whether the process is a known JIT app (info-level alerts)",
     "Export forensics on the process",
     "Kill + block if the process is not a browser/runtimes"],
    ["Vérifier si le processus est une app JIT connue (alertes info)",
     "Exporter le forensique du processus",
     "Tuer + bloquer si ce n'est pas un navigateur/runtime"]),

"MODULE_SUSPECT": _e(
    "Module loaded from a staging path",
    "Module chargé depuis un chemin de staging",
    "A file-backed library inside the process lives in a location executable "
    "code should never use: temp dirs, /dev/shm, Downloads, browser caches — "
    "classic dropper/injection staging.",
    "Une bibliothèque chargée dans le processus vit dans un emplacement où du "
    "code exécutable ne devrait jamais être : temp, /dev/shm, Downloads, "
    "caches de navigateurs — staging classique de dropper/injection.",
    "Legitimate apps keep their DLLs/.so under Program Files, /usr/lib or "
    "their own bundle — almost nothing real loads code from %TEMP%.",
    "Les applications légitimes gardent leurs DLL/.so sous Program Files, "
    "/usr/lib ou leur propre bundle — presque rien de réel ne charge du code "
    "depuis %TEMP%.",
    ["List the flagged module paths in the finding",
     "Hash the modules and check them against VirusTotal yourself",
     "Kill + firewall the process if the module is unexpected"],
    ["Lister les chemins de modules signalés dans le constat",
     "Hasher les modules et les vérifier sur VirusTotal soi-même",
     "Tuer + bloquer le processus si le module est inattendu"]),

"MODULE_CHANGED": _e(
    "Mapped-module set changed",
    "Ensemble de modules modifié",
    "The Merkle root over this process's file-backed modules changed versus "
    "its recorded baseline — a DLL/.so was replaced on disk or a new module "
    "appeared since baseline.",
    "La racine Merkle des modules fichier-basés du processus a changé par "
    "rapport à la baseline — une DLL/.so a été remplacée sur disque ou un "
    "nouveau module est apparu.",
    "Updates legitimately swap modules — correlate with a recent software "
    "update. Absent one, an in-session module swap is a strong tamper signal.",
    "Les mises à jour remplacent légitimement des modules — corréler avec une "
    "update récente. Sans elle, un remplacement en session est un fort signal "
    "d'altération.",
    ["Check for a recent app/OS update covering these modules",
     "Compare expected vs actual roots in the finding",
     "Export forensics for the module list"],
    ["Vérifier une mise à jour récente couvrant ces modules",
     "Comparer les racines attendue/réelle dans le constat",
     "Exporter le forensique pour la liste des modules"]),

"MINING_STRATUM": _e(
    "Cleartext mining protocol observed",
    "Protocole de minage en clair observé",
    "The connection payload contains the JSON-RPC stratum dialect miners "
    "speak to pools (\"mining.subscribe\", \"mining.authorize\"…) — a "
    "near-conclusive cryptomining signature.",
    "Le payload de la connexion contient le dialecte JSON-RPC stratum que les "
    "mineurs parlent aux pools (« mining.subscribe », « mining.authorize »…) "
    "— signature quasi-concluante de cryptominage.",
    "Nothing legitimate speaks stratum on a workstation. Encrypted stratum "
    "(TLS) stays invisible to this check — cleartext is what miners still "
    "use on many pools.",
    "Rien de légitime ne parle stratum sur un poste. Le stratum chiffré (TLS) "
    "reste invisible à ce contrôle — le clair reste utilisé par beaucoup de "
    "pools.",
    ["Identify the process and kill it if unwanted",
     "Block the pool IP/port with a firewall rule",
     "Export forensics — miners usually reinstall via a dropper"],
    ["Identifier le processus et le tuer s'il est indésirable",
     "Bloquer l'IP/port du pool par une règle pare-feu",
     "Exporter le forensique — les mineurs se réinstallent via dropper"]),

"MINING_SUSPECT": _e(
    "Pool port + sustained CPU",
    "Port de pool + CPU soutenue",
    "A process keeps talking to a well-known mining-pool port while burning "
    "sustained CPU — the combination is suspect even though neither signal "
    "alone would be.",
    "Un processus parle à un port de pool de minage connu tout en brûlant de "
    "la CPU de façon soutenue — la combinaison est suspecte, même si aucun "
    "signal seul ne le serait.",
    "IRC/game traffic shares pool ports legitimately — sustained high CPU is "
    "the corroboration. A warning, not a verdict.",
    "Le trafic IRC/jeu partage ces ports légitimement — la CPU soutenue est "
    "la corroboration. Un avertissement, pas un verdict.",
    ["Check the process's CPU in the process list",
     "Run a perf sample (/security/perf) for hardware counters",
     "Block the destination if the usage is unexplained"],
    ["Vérifier la CPU du processus dans la liste",
     "Lancer un échantillon perf (/security/perf) pour les compteurs",
     "Bloquer la destination si l'usage est inexpliqué"]),

"SINKHOLE_HIT": _e(
    "Sinkholed connection observed",
    "Connexion sinkholée observée",
    "A process connected to a destination you sinkholed — the loopback "
    "responder captured its HTTP Host/path or TLS SNI, revealing what the "
    "blocked app was trying to reach.",
    "Un processus s'est connecté à une destination sinkholée — le répondeur "
    "loopback a capturé son Host/chemin HTTP ou SNI TLS, révélant ce que "
    "l'appli bloquée cherchait.",
    "This is the sinkhole doing its job: the attempt is contained AND "
    "observed. Repeated hits from one process deserve a process-level rule.",
    "C'est le sinkhole qui fait son travail : la tentative est contenue ET "
    "observée. Des hits répétés d'un même processus méritent une règle "
    "processus.",
    ["Read the captured host/path in the finding",
     "Create a process rule if the same app keeps retrying",
     "Deep-inspect the process if it adapts to the sinkhole"],
    ["Lire l'hôte/chemin capturé dans le constat",
     "Créer une règle processus si l'app retente sans cesse",
     "Inspecter le processus s'il s'adapte au sinkhole"]),

"INJECT_SUSPECT": _e(
    "Connection from a staged module",
    "Connexion depuis un module stagé",
    "During deep inspection, an outbound connection originated from a module "
    "loaded out of a temp/cache/download staging path — the signature of "
    "injected code phoning home through a legit-looking process.",
    "Pendant l'inspection profonde, une connexion sortante provenait d'un "
    "module chargé depuis un chemin de staging temp/cache/download — la "
    "signature de code injecté qui appelle sa base via un processus "
    "d'apparence légitime.",
    "This is Frida-level evidence, not a packet guess: the calling module "
    "itself was resolved. Almost no legitimate software connects from %TEMP%.",
    "C'est une preuve de niveau Frida, pas une estimation paquet : le module "
    "appelant lui-même a été résolu. Presque aucun logiciel légitime ne "
    "connecte depuis %TEMP%.",
    ["Review the flagged module paths",
     "Kill the host process and quarantine the module file",
     "Expect re-injection — check the parent process tree"],
    ["Examiner les chemins de modules signalés",
     "Tuer le processus hôte et mettre le module en quarantaine",
     "Anticiper la réinjection — vérifier l'arbre des processus parents"]),

"COMMUNITY_IOC": _e(
    "Community pack hint",
    "Indice du paquet communautaire",
    "A destination matched a shared IOC pack — Bloom + randomized response "
    "means membership is probabilistic, not proof.",
    "Une destination a correspondu à un paquet d'IOC partagé — Bloom + "
    "randomized response rendent l'appartenance probabiliste, pas certaine.",
    "Treat as a hint: false positives are expected by design. Corroborate "
    "with local signals before acting.",
    "À traiter comme un indice : les faux positifs sont attendus par "
    "conception. Corroborer avec des signaux locaux avant d'agir.",
    ["Run a local reputation check on the indicator",
     "Watch the destination before blocking"],
    ["Lancer une vérif de réputation locale sur l'indicateur",
     "Surveiller la destination avant de bloquer"]),

"CUSTOM_RULE": _e(
    "Your rule matched",
    "Votre règle a correspondu",
    "A packet matched a condition YOU defined in the alert-rules panel "
    "(field + operator + value). This is your own detection firing — "
    "not a built-in heuristic.",
    "Un paquet a correspondu à une condition que VOUS avez définie dans "
    "le panneau de règles (champ + opérateur + valeur). C'est votre propre "
    "détection qui se déclenche — pas une heuristique intégrée.",
    "Default rules only alert; rules with the block action additionally "
    "install a firewall rule on the remote host. Tune field/op/value if "
    "it fires too often, or disable it from the rules list.",
    "Par défaut la règle ne fait qu'alerter ; une règle avec l'action "
    "« block » installe de plus une règle pare-feu sur l'hôte distant. "
    "Ajustez champ/op/valeur si elle se déclenche trop, ou désactivez-la.",
    ["Check which process triggered it",
     "Tighten the matcher if noisy",
     "Review any firewall rule it auto-created"],
    ["Vérifier quel processus l'a déclenchée",
     "Resserrer le filtre si trop bavarde",
     "Revoir la règle pare-feu auto-créée le cas échéant"]),

"TLS_CERT": _e(
    "TLS certificate anomaly",
    "Anomalie du certificat TLS",
    "The server presented a leaf certificate that is self-signed or whose "
    "SANs do not cover the requested SNI — observed passively from the "
    "handshake, no interception involved.",
    "Le serveur a présenté un certificat feuille auto-signé ou dont les "
    "SANs ne couvrent pas le SNI demandé — observé passivement sur le "
    "handshake, sans interception.",
    "Self-signed certs are normal on internal tools and dev boxes; on a "
    "public service they can mean MitM or a C2 with a throwaway cert. A "
    "SAN/SNI mismatch means the endpoint answered with someone else's "
    "certificate — suspicious on real services.",
    "L'auto-signé est normal sur les outils internes et dev ; sur un "
    "service public cela peut indiquer un MitM ou un C2 à cert jetable. "
    "Un mismatch SAN/SNI signifie que l'endpoint a répondu avec le "
    "certificat d'un autre — suspect sur un vrai service.",
    ["Check the issuer shown in the alert",
     "Verify the site loads correctly in a browser",
     "Block the IP if the endpoint cannot be explained",
     "Note: TLS 1.3 encrypts this message — absence of alert is not proof"],
    ["Vérifier l'émetteur affiché dans l'alerte",
     "Vérifier que le site se charge normalement dans un navigateur",
     "Bloquer l'IP si l'endpoint est inexplicable",
     "NB : TLS 1.3 chiffre ce message — l'absence d'alerte n'est pas une preuve"]),

"HIGH_ENTROPY": _e(
    "Encrypted-looking data on a cleartext channel",
    "Données d'apparence chiffrée sur un canal en clair",
    "The first payload bytes on a non-TLS socket are statistically "
    "near-random — real plaintext protocols are structured and compress "
    "well, so this suggests covert encryption, packed data or stego.",
    "Les premiers octets du payload sur une socket non TLS sont "
    "statistiquement quasi aléatoires — un vrai protocole clair est "
    "structuré ; cela suggère du chiffrement couvert, des données packées "
    "ou de la stéganographie.",
    "Info-level by design: compressed uploads (zip, video, protobuf) "
    "trigger it legitimately. It matters when an unexpected process "
    "produces it.",
    "Niveau info par conception : les envois compressés (zip, vidéo, "
    "protobuf) la déclenchent légitimement. Elle compte quand un "
    "processus inattendu la produit.",
    ["Check which process is sending",
     "Correlate with destination and other alerts",
     "Ignore for known compression-heavy apps"],
    ["Vérifier quel processus envoie",
     "Corréler avec la destination et les autres alertes",
     "Ignorer pour les apps connues très compressées"]),

"ICMP_TUNNEL": _e(
    "Possible ICMP tunnelling",
    "Tunnel ICMP possible",
    "Repeated ICMP echo packets carrying unusually large payloads — real "
    "echo traffic is tiny; fat echoes are the classic signature of ICMP "
    "exfiltration tools (ptunnel, icmpsh).",
    "Paquets d'écho ICMP répétés avec des payloads anormalement gros — "
    "l'écho réel est minuscule ; de gros échos sont la signature "
    "classique des outils d'exfiltration ICMP (ptunnel, icmpsh).",
    "ICMP passes where TCP/UDP are filtered, making it a favourite "
    "covert channel. Requires several fat echoes to fire, so a single "
    "odd ping stays quiet.",
    "L'ICMP passe là où TCP/UDP sont filtrés — canal couvert favori. "
    "Plusieurs gros échos requis pour déclencher, un ping isolé reste muet.",
    ["Identify which host pair is talking",
     "Check whether diagnostic tooling runs ICMP here",
     "Block ICMP to that peer with a firewall rule if confirmed"],
    ["Identifier la paire d'hôtes qui communique",
     "Vérifier qu'un outil de diagnostic n'utilise pas ICMP ici",
     "Bloquer l'ICMP vers ce pair si confirmé"]),

"ML_ANOMALY": _e(
    "Flow unlike this machine's baseline",
    "Flux atypique vs la baseline de la machine",
    "A pure-Python isolation forest scored this outbound flow as an "
    "outlier against YOUR OWN recent traffic — unusual port, interval, "
    "size pattern or fan-out. Unsupervised: it learned what YOUR machine "
    "looks like, not what malware looks like.",
    "Une forêt d'isolation pur Python a scoré ce flux sortant comme "
    "outlier face à VOTRE propre trafic récent — port, intervalle, taille "
    "ou fan-out inhabituels. Non supervisé : elle a appris à quoi "
    "ressemble VOTRE machine, pas ce à quoi ressemble un malware.",
    "Complements the heuristics — it can catch patterns no rule was "
    "written for, but unusual-but-legit software (new apps, rare "
    "backups) will also stand out early on. It needs a few hundred flows "
    "before it scores anything.",
    "Complète les heuristiques — elle peut attraper des motifs pour "
    "lesquels aucune règle n'existe, mais le logiciel inhabituel-et-"
    "légitime ressort aussi au début. Quelques centaines de flux sont "
    "requis avant le premier score.",
    ["Compare with what changed on the machine recently",
     "Check the process against the integrity tools",
     "Expect noise in the first days — it sharpens with uptime"],
    ["Comparer avec ce qui a changé récemment sur la machine",
     "Vérifier le processus avec les outils d'intégrité",
     "Bruit attendu les premiers jours — se raffine avec le temps"]),

"ASK_VERDICT": _e(
    "New flow awaiting your verdict",
    "Nouveau flux en attente de verdict",
    "Ask-on-first-connect is enabled: the kernel handed this packet to "
    "Snitch instead of letting it through. It is genuinely suspended "
    "until you answer — this is real verdict power, not a notification.",
    "Le mode ask-on-first-connect est actif : le noyau a remis ce paquet "
    "à Snitch au lieu de le laisser passer. Il est réellement suspendu "
    "jusqu'à votre réponse — vrai pouvoir de verdict, pas une notif.",
    "Only the FIRST packet of each flow waits — decide once and the rest "
    "of the connection rides your decision for the session. Unanswered "
    "flows hit the timeout policy (drop by default).",
    "Seul le PREMIER paquet de chaque flux attend — décidez une fois et "
    "le reste de la connexion suit votre décision pour la session. Les "
    "flux sans réponse subissent la politique de timeout (drop par défaut).",
    ["Allow once or deny from the prompt",
     "Create a firewall rule for permanent decisions",
     "Linux/NFQUEUE only — see /security/ask for platform status"],
    ["Autoriser ou refuser depuis le prompt",
     "Créer une règle pare-feu pour les décisions permanentes",
     "Linux/NFQUEUE seulement — voir /security/ask pour le statut"]),

"DGA_SUSPECT": _e(
    "Domain looks algorithmically generated",
    "Domaine à aspect généré algorithmiquement",
    "The resolved name or TLS SNI fails lexical checks typical of domain-"
    "generation algorithms: high entropy, almost no vowels, stacked "
    "consonants, digit noise — how malware C2 hostnames usually look.",
    "Le nom résolu ou le SNI TLS échoue aux contrôles lexicaux typiques "
    "des algorithmes de génération de domaines : entropie élevée, quasi "
    "aucune voyelle, consonnes empilées, chiffres — le look classique "
    "des C2 de malware.",
    "Pure local heuristic — no WHOIS, no domain-age data. Legit-but-"
    "weird names (hashes, build artifacts) can trip it occasionally; the "
    "finding is info-level and cooled down per name.",
    "Heuristique purement locale — ni WHOIS ni âge du domaine. Des noms "
    "légitimes bizarres (hachés, artefacts de build) peuvent déclencher "
    "occasionnellement ; niveau info, cooldown par nom.",
    ["Check which process resolved it",
     "Look for follow-up connections to the resolved IP",
     "Ignore once for known dev/build tools"],
    ["Vérifier quel processus l'a résolu",
     "Surveiller les connexions vers l'IP résolue",
     "Ignorer une fois pour les outils de build connus"]),

"PROTO_MISMATCH": _e(
    "Payload does not match the port's protocol",
    "Payload non conforme au protocole du port",
    "The first bytes on this socket do not look like the protocol the "
    "port advertises — non-HTTP on :80, non-TLS on :443, non-DNS on :53, "
    "non-SSH on :22… Attackers hide tunnels on friendly ports to slip "
    "past firewall rules.",
    "Les premiers octets de cette socket ne ressemblent pas au protocole "
    "annoncé par le port — non-HTTP sur :80, non-TLS sur :443, non-DNS "
    "sur :53, non-SSH sur :22… Les attaquants planquent des tunnels sur "
    "des ports amicaux pour passer les pare-feux.",
    "Heuristic on the ≤64-byte head only — exotic legit protocols "
    "(WebSocket upgrades, custom daemons) may trip it once, then the "
    "cooldown keeps it quiet.",
    "Heuristique sur la tête ≤64 o seulement — des protocoles légitimes "
    "exotiques (upgrades WebSocket, démons custom) peuvent déclencher une "
    "fois puis le cooldown les tait.",
    ["Inspect the process — legit apps use their own ports",
     "Correlate with HIGH_ENTROPY/DNS_TUNNEL on the same host",
     "Block the flow if the process can't be explained"],
    ["Inspecter le processus — les apps légitimes utilisent leurs ports",
     "Corréler avec HIGH_ENTROPY/DNS_TUNNEL sur le même hôte",
     "Bloquer le flux si le processus est inexplicable"]),
}


def explain(alert_type: str) -> dict | None:
    """EN: Explanation record for one alert type — None when unknown.
    FR: Explication pour un type d'alerte — None si inconnu."""
    return EXPLANATIONS.get((alert_type or "").upper())


def all_types() -> list[str]:
    """EN: Alert types with an explanation — used by the audit endpoint.
    FR: Types d'alertes documentés — utilisé par l'endpoint d'audit."""
    return sorted(EXPLANATIONS)
