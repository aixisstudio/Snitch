/**
 * Snitch — internationalization (English / Français).
 *
 * EN: Tiny homemade i18n layer. Two flat dictionaries (`en` / `fr`) keyed by
 *     string. Values can be plain strings or functions for interpolation,
 *     e.g. t('lan_devices', 3) → "3 devices LAN" / "3 devices LAN".
 *     `useT()` returns { lang, t, setLang } to any component.
 * FR: Petite couche i18n maison. Deux dictionnaires plats (`en` / `fr`) indexés
 *     par chaîne. Les valeurs peuvent être des chaînes simples ou des fonctions
 *     pour l'interpolation, ex. t('lan_devices', 3) → "3 devices LAN".
 *     `useT()` renvoie { lang, t, setLang } à tout composant.
 */
import { createContext, useContext, useState } from 'react'

// ── English dictionary / Dictionnaire anglais ────────────────────────────────
const en = {
  // Navigation
  nav_graph: 'Graph',
  nav_map: 'Map',

  // Status badge / Badge de statut
  status_connected: 'Live',
  status_connecting: 'Connecting…',
  status_disconnected: 'Disconnected',
  status_error: 'Error',
  lan_devices: n => `${n} device${n > 1 ? 's' : ''} LAN`,

  // Legend / Légende
  legend_alert: 'Alert',
  legend_unknown: 'Unknown',
  legend_router: 'Router',
  legend_phone: 'Phone',
  legend_pc: 'PC',
  legend_iot: 'IoT',
  legend_https: 'HTTPS',
  legend_tracking: 'Tracking',
  legend_cdn: 'CDN',
  legend_dns: 'DNS',

  // Sidebar header + stats / En-tête de barre latérale + stats
  app_name: 'SNITCH',
  tagline: "Track every hidden flow.",
  footer_credit: 'Developed by aiXis',
  stat_lan: 'LAN Devices',
  stat_ext: 'Ext. hosts',
  stat_traffic: 'Traffic',

  // Sidebar sections / Sections de la barre latérale
  section_lan: n => `LAN Devices (${n})`,
  section_ext: (n, total) => total ? `External hosts (${n}/${total})` : `External hosts (${n})`,
  section_packets: 'Recent traffic',

  // Node detail field labels / Étiquettes des champs de détail de nœud
  field_ip: 'IP',
  field_mac: 'MAC',
  field_hostname: 'Hostname',
  field_vendor: 'Vendor',
  field_type: 'Type',
  field_country: 'Country',
  field_city: 'City',
  field_org: 'Org',
  field_category: 'Category',
  field_traffic: 'Traffic',
  field_packets: 'Packets',
  processes: 'Processes',
  online: 'online',
  offline: 'offline',

  // Search / Recherche
  search_placeholder: 'Search host, IP, country…',
  cat_all: 'All',
  cat_unknown: 'Unknown',
  cat_alerted: 'Alerts',
  cat_safe: 'Safe',
  cat_tracking: 'Tracking',
  cat_cdn: 'CDN',
  cat_dns: 'DNS',
  cat_admin: 'Admin',
  cat_local: 'Local',
  cat_lan_device: 'LAN device',
  cat_other: 'Other',

  // EN: Node names + identification hints shown to the user.
  // FR: Noms de nœuds + indices d'identification affichés à l'utilisateur.
  node_local: 'This Device',
  hint_local: 'This is THIS machine — the one running Snitch. Everything it sends or receives radiates from the center of the graph.',
  unidentified: 'unidentified',
  devtype_router: 'Router',
  devtype_phone: 'Phone',
  devtype_pc: 'Computer',
  devtype_tv: 'TV',
  devtype_iot: 'IoT device',
  devtype_unknown: 'Unknown type',
  hint_unidentified: "Not identified yet — its name appears when it announces itself (DNS/mDNS) or its MAC vendor is known. If you don't recognize it, check your router's client list.",
  hint_unresolved: 'Not yet named — the domain appears when a DNS answer or TLS handshake reveals it.',
  hint_private_mac: 'Private (randomized) MAC address — iOS/Android/Windows hide the real one, so the vendor can\'t be identified. This is normal privacy behavior.',
  hint_gateway: 'This is your internet box/router — ALL your traffic physically passes through it, so seeing it communicate is normal and expected.',
  hint_lan_idle: 'Seen on your network via the neighbour table — no data exchanged. A dashed edge means "present", not "talking".',
  hint_lan_active: b => `${b} exchanged — usually automatic announcements (Bonjour/mDNS, file sharing). Watch it if the volume climbs.`,
  ext_empty: "No external connections yet — anything your machine talks to will appear here.",
  legend_edge_solid: 'solid line = traffic',
  legend_edge_dashed: 'dashed = seen, no data',
  legend_ring_safe: 'green ring = identified, safe',
  legend_ring_warn: 'amber ring = suspicious',
  legend_ring_crit: 'red ring = alert',
  legend_ring_none: 'no ring = unidentified, neutral',
  legend_perimeter: 'LAN perimeter',
  perim_lan: 'LOCAL NETWORK',

  // Alert panel / Panneau d'alertes
  alerts_title: 'Alerts',
  alerts_total: 'total',
  alerts_empty: 'No alerts yet',
  alert_NEW_HOST: 'New host',
  alert_SUSPICIOUS_PROCESS: 'Suspicious process',
  alert_SUSPICIOUS_PORT: 'Suspicious port',
  alert_BEACON: 'Beacon C2',
  alert_VOLUME_SPIKE: 'Traffic spike',
  alert_NEW_LAN_DEVICE: 'New device',
  alert_DEVICE_OFFLINE: 'Device offline',
  alert_MEDIA_EXFIL: 'Media exfiltration',
  alert_PORT_SCAN: 'Port scan',
  alert_UPLOAD_SPIKE: 'Upload spike',
  alert_WATCHLIST_HIT: 'Watchlist hit',
  // EN: Full alert messages built from backend codes + details — the backend
  //     only sends type + params, never prose.
  // FR: Messages d'alerte complets construits depuis les codes + détails du
  //     backend — le backend n'envoie que type + paramètres, jamais de prose.
  alertmsg_NEW_HOST: d => `New host contacted: ${d.host || d.ip}`,
  alertmsg_SUSPICIOUS_PROCESS: d => `Suspicious process: ${d.process} → ${d.host || d.ip}`,
  alertmsg_SUSPICIOUS_PORT: d => `Suspicious port ${d.port} (${d.reason}) → ${d.host || d.ip}`,
  alertmsg_BEACON: d => `Beacon-like regularity: ~${d.interval_s}s interval to ${d.host || d.ip}`,
  alertmsg_VOLUME_SPIKE: d => `Data spike to ${d.host || d.ip}: ${Math.round((d.bytes || 0) / 1024)} KB in ${d.window_s}s`,
  alertmsg_MEDIA_EXFIL: d => `Suspected ${d.device} exfiltration: ${d.process} → ${d.host || d.ip}`,
  alertmsg_NEW_LAN_DEVICE: d => `New device on the network: ${d.host || d.ip}`,
  alertmsg_DEVICE_OFFLINE: d => `Device went offline: ${d.host || d.ip}`,
  alertmsg_PORT_SCAN: d => `Port scan: ${d.source || d.ip} touched ${d.ports}+ ports in ${d.window_s}s`,
  alertmsg_UPLOAD_SPIKE: d => `Upload spike: ${d.process} sent ${d.mb} MB in ${d.window_s}s`,
  alertmsg_WATCHLIST_HIT: d => `Watchlist hit: ${d.match} (${d.host || d.ip}) — ${d.process || 'unknown process'}`,
  time_just_now: 'just now',
  time_seconds: n => `${n}s ago`,
  time_minutes: n => `${n}min ago`,
  time_hours: n => `${n}h ago`,

  // Privacy score / Score de confidentialité
  privacy_title: 'Privacy Score',
  privacy_critical_label: 'Critical',
  privacy_excellent_label: 'Excellent',
  privacy_risk_factors: n => `${n} risk factor${n !== 1 ? 's' : ''}`,
  privacy_more_factors: n => `+${n} more factor${n > 1 ? 's' : ''}`,
  privacy_label_excellent: 'Excellent',
  privacy_label_good: 'Good',
  privacy_label_average: 'Average',
  privacy_label_weak: 'Weak',
  privacy_label_critical: 'Critical',

  // Timeline
  timeline_packets: n => `${n.toLocaleString()} packets`,
  timeline_alerts: n => `${n} alert${n > 1 ? 's' : ''}`,
  timeline_live: 'Live',

  // Capture toggle / Bascule de capture
  capture_stop: 'Stop',
  capture_start: 'Start',
  capture_stopping: 'Stopping…',
  capture_starting: 'Starting…',

  // Port filter / Filtre de ports
  port_filter: 'Ports',
  port_all: 'All ports',
  port_placeholder: 'Add port (e.g. 443)',
  port_invalid: 'Invalid port',

  // Export
  export_btn: 'Export',
  export_graph_json: 'Graph (JSON)',
  export_graph_csv: 'Graph (CSV)',
  export_alerts_json: 'Alerts (JSON)',
  export_alerts_csv: 'Alerts (CSV)',

  // Process filter / Filtre de processus
  process_filter: 'Apps',
  process_filter_hint: 'Click to hide app from graph',
  process_none: 'No processes detected yet',
  process_clear: 'Show all apps',

  // IP whitelist / Liste blanche d'IP
  ip_whitelist: 'Trusted',
  ip_whitelist_hint: 'Trusted IPs are no longer captured or shown',
  ip_placeholder: 'Add IP (e.g. 1.1.1.1)',
  ip_invalid: 'Invalid IP address',
  ip_clear: 'Clear whitelist',
  whitelist_action: 'Mark as trusted',

  // Map / Carte
  map_you: 'You',
  map_located: n => `${n} located host${n !== 1 ? 's' : ''}`,
  map_no_geo: 'no geo',

  // Scoring factor labels / Libellés des facteurs de score
  score_trackers: n => `${n} tracker${n > 1 ? 's' : ''} contacted`,
  score_tracker_traffic: pct => `${pct}% traffic to trackers`,
  score_ad_networks: n => `${n} ad network${n > 1 ? 's' : ''}`,
  score_beacons: n => `${n} beacon behavior${n > 1 ? 's' : ''}`,
  score_susp_proc: n => `${n} suspicious process${n > 1 ? 'es' : ''}`,
  score_susp_ports: n => `${n} dangerous port${n > 1 ? 's' : ''}`,
  score_critical_alerts: n => `${n} critical alert${n > 1 ? 's' : ''}`,
  score_warnings: n => `${n} warnings`,
  score_https_ratio: pct => `${pct}% HTTPS traffic`,
  score_no_trackers: 'No trackers detected',

  // Settings / Réglages
  settings_title: 'Settings',
  settings_saved: 'Saved',
  close: 'Close',
  settings_language: 'Language / Langue',
  theme_toggle: 'Light / dark theme',
  settings_retention: 'History retention',
  settings_retention_hint: 'How long traffic & alert history is kept',
  settings_interface: 'Capture interface',
  settings_interface_hint: 'Which network adapter is sniffed (restart capture to apply)',
  settings_interface_auto: 'Auto (first non-loopback)',
  settings_upload: 'Upload alert threshold',
  settings_upload_hint: 'Warn when one process uploads more than this per minute',
  settings_off: 'Off',
  watchlist_title: 'Watchlist',
  watchlist_hint: 'Get alerted whenever traffic touches these IPs or domains',
  watchlist_placeholder: '203.0.113.7 or example.com',
  watchlist_add: 'Add',
  watchlist_remove: 'Remove',
  update_title: 'Updates',
  update_checking: 'Checking for updates…',
  update_available: v => `Update available: v${v} — downloading`,
  update_downloading: p => `Downloading update… ${p}%`,
  update_ready: v => `v${v} downloaded — restart to install`,
  update_none: 'Snitch is up to date',
  update_error: 'Update check failed',
  update_idle: 'No check yet',
  update_restart: 'Restart & install',
  update_check_btn: 'Check now',
  update_auto: 'Check automatically',
  update_privacy: 'Checks github.com for new releases — the only outbound call besides the GeoIP download.',
  geo_title: 'Geolocation database',
  geo_present: dbs => `Installed: ${dbs}`,
  geo_none: 'Not installed — IPs are not geolocated',
  geo_download_btn: 'Download DB-IP Lite (free)',
  geo_consent: 'Downloads ~50 MB from db-ip.com (CC BY 4.0). This is the only outbound call Snitch can make.',
  geo_downloading: 'Downloading…',
  geo_done: n => `Downloaded ${n} database(s)`,
  geo_failed: 'Download failed — check your connection',
  diag_title: 'Diagnostics',
  diag_hint: 'Logs and system info for bug reports',
  diag_open_logs: 'Logs',
  diag_export: 'Export',
  settings_note: 'All settings are stored locally. Snitch never sends data to third parties.',
  nav_apps: 'Apps',
  ignore_alert: 'Ignore this alert type/host',

  // Apps view / Vue applications
  apps_empty: 'No process attributed yet',
  apps_process: 'Process',
  apps_destinations: 'Hosts',
  apps_packets: 'Packets',
  apps_volume: 'Volume',
  apps_top_dest: 'Top destinations',
  apps_history_60m: 'Last hour (bytes/min)',
  alertmsg_NEW_HOSTS: n => `${n} new host${n > 1 ? 's' : ''} contacted`,
  settings_autolaunch: 'Launch at login',
  settings_autolaunch_hint: 'Start Snitch automatically when you sign in',

  // Onboarding / Premier lancement
  onboard_title: 'Welcome to Snitch',
  onboard_sub: 'Real-time network traffic visualizer — private by design.',
  onboard_priv_title: 'Everything stays on this machine',
  onboard_priv_body: 'Traffic metadata, alerts and history are stored in a local SQLite database. No account, no cloud, no telemetry.',
  onboard_capture_title: 'What is captured',
  onboard_capture_body: 'Packet headers only: destination IPs, ports, volumes, process names, DNS names and TLS server names (SNI). Payloads are never read.',
  onboard_out_title: 'What leaves the machine',
  onboard_out_body: 'Nothing by default. The only possible outbound call is the geolocation database download, which you trigger yourself in Settings.',
  onboard_go: 'Got it',
}

// ── Dictionnaire français / French dictionary ────────────────────────────────
const fr = {
  // Navigation
  nav_graph: 'Graphe',
  nav_map: 'Carte',

  // Badge de statut / Status badge
  status_connected: 'En direct',
  status_connecting: 'Connexion…',
  status_disconnected: 'Déconnecté',
  status_error: 'Erreur',
  lan_devices: n => `${n} appareil${n > 1 ? 's' : ''} LAN`,

  // Légende / Legend
  legend_alert: 'Alerte',
  legend_unknown: 'Inconnu',
  legend_router: 'Routeur',
  legend_phone: 'Téléphone',
  legend_pc: 'PC',
  legend_iot: 'IoT',
  legend_https: 'HTTPS',
  legend_tracking: 'Pistage',
  legend_cdn: 'CDN',
  legend_dns: 'DNS',

  // En-tête de barre latérale + stats / Sidebar header + stats
  app_name: 'SNITCH',
  tagline: 'Traquez chaque flux masqué.',
  footer_credit: 'Développé par aiXis',
  stat_lan: 'Appareils LAN',
  stat_ext: 'Hôtes ext.',
  stat_traffic: 'Trafic',

  // Sections de la barre latérale / Sidebar sections
  section_lan: n => `Appareils LAN (${n})`,
  section_ext: (n, total) => total ? `Hôtes externes (${n}/${total})` : `Hôtes externes (${n})`,
  section_packets: 'Flux récents',

  // Étiquettes des champs de détail de nœud / Node detail field labels
  field_ip: 'IP',
  field_mac: 'MAC',
  field_hostname: 'Nom d\'hôte',
  field_vendor: 'Fabricant',
  field_type: 'Type',
  field_country: 'Pays',
  field_city: 'Ville',
  field_org: 'Org',
  field_category: 'Catégorie',
  field_traffic: 'Trafic',
  field_packets: 'Paquets',
  processes: 'Processus',
  online: 'en ligne',
  offline: 'hors ligne',

  // Recherche / Search
  search_placeholder: 'Rechercher hôte, IP, pays…',
  cat_all: 'Tout',
  cat_unknown: 'Inconnu',
  cat_alerted: 'Alertes',
  cat_safe: 'Sûr',
  cat_tracking: 'Pistage',
  cat_cdn: 'CDN',
  cat_dns: 'DNS',
  cat_admin: 'Admin',
  cat_local: 'Local',
  cat_lan_device: 'Appareil LAN',
  cat_other: 'Autre',

  // FR: Noms de nœuds + indices d'identification affichés à l'utilisateur.
  // EN: Node names + identification hints shown to the user.
  node_local: 'Cet appareil',
  hint_local: "C'est CETTE machine — celle qui fait tourner Snitch. Tout ce qu'elle envoie ou reçoit rayonne depuis le centre du graphe.",
  unidentified: 'non identifié',
  devtype_router: 'Routeur',
  devtype_phone: 'Téléphone',
  devtype_pc: 'Ordinateur',
  devtype_tv: 'TV',
  devtype_iot: 'Objet connecté',
  devtype_unknown: 'Type inconnu',
  hint_unidentified: "Pas encore identifié — son nom apparaîtra s'il s'annonce (DNS/mDNS) ou si son fabricant est connu. Si vous ne le reconnaissez pas, vérifiez la liste des clients de votre box/routeur.",
  hint_unresolved: "Pas encore nommé — le domaine apparaîtra quand une réponse DNS ou un handshake TLS le révélera.",
  hint_private_mac: "Adresse MAC privée (aléatoire) — iOS/Android/Windows masquent la vraie, le fabricant ne peut pas être identifié. C'est un comportement de confidentialité normal.",
  hint_gateway: "C'est votre box/routeur — TOUT votre trafic internet passe physiquement par elle, donc la voir communiquer est normal et attendu.",
  hint_lan_idle: "Vu sur votre réseau via la table de voisinage — aucune donnée échangée. Une arête en pointillés signifie « présent », pas « en train de communiquer ».",
  hint_lan_active: b => `${b} échangés — le plus souvent des annonces automatiques (Bonjour/mDNS, partage de fichiers). À surveiller si le volume grimpe.`,
  ext_empty: "Aucune connexion externe pour l'instant — tout hôte contacté par votre machine apparaîtra ici.",
  legend_edge_solid: 'trait plein = trafic',
  legend_edge_dashed: 'pointillés = vu, sans données',
  legend_ring_safe: 'anneau vert = identifié, sûr',
  legend_ring_warn: 'anneau orange = suspect',
  legend_ring_crit: 'anneau rouge = alerte',
  legend_ring_none: 'sans anneau = non identifié, neutre',
  legend_perimeter: 'périmètre LAN',
  perim_lan: 'RÉSEAU LOCAL',

  // Panneau d'alertes / Alert panel
  alerts_title: 'Alertes',
  alerts_total: 'total',
  alerts_empty: "Aucune alerte pour l'instant",
  alert_NEW_HOST: 'Nouvel hôte',
  alert_SUSPICIOUS_PROCESS: 'Processus suspect',
  alert_SUSPICIOUS_PORT: 'Port suspect',
  alert_BEACON: 'Beacon C2',
  alert_VOLUME_SPIKE: 'Pic de trafic',
  alert_NEW_LAN_DEVICE: 'Nouvel appareil',
  alert_DEVICE_OFFLINE: 'Appareil hors ligne',
  alert_MEDIA_EXFIL: 'Exfiltration média',
  alert_PORT_SCAN: 'Scan de ports',
  alert_UPLOAD_SPIKE: 'Pic d\'envoi',
  alert_WATCHLIST_HIT: 'Correspondance watchlist',
  alertmsg_NEW_HOST: d => `Nouvel hôte contacté : ${d.host || d.ip}`,
  alertmsg_SUSPICIOUS_PROCESS: d => `Processus suspect : ${d.process} → ${d.host || d.ip}`,
  alertmsg_SUSPICIOUS_PORT: d => `Port suspect ${d.port} (${d.reason}) → ${d.host || d.ip}`,
  alertmsg_BEACON: d => `Régularité type beacon : intervalle ~${d.interval_s}s vers ${d.host || d.ip}`,
  alertmsg_VOLUME_SPIKE: d => `Pic de données vers ${d.host || d.ip} : ${Math.round((d.bytes || 0) / 1024)} Ko en ${d.window_s}s`,
  alertmsg_PORT_SCAN: d => `Scan de ports : ${d.source || d.ip} a touché ${d.ports}+ ports en ${d.window_s}s`,
  alertmsg_MEDIA_EXFIL: d => `Exfiltration ${d.device === 'camera' ? 'caméra' : 'micro'} suspectée : ${d.process} → ${d.host || d.ip}`,
  alertmsg_NEW_LAN_DEVICE: d => `Nouvel appareil sur le réseau : ${d.host || d.ip}`,
  alertmsg_DEVICE_OFFLINE: d => `Appareil hors ligne : ${d.host || d.ip}`,
  alertmsg_UPLOAD_SPIKE: d => `Pic d\'envoi : ${d.process} a envoyé ${d.mb} Mo en ${d.window_s}s`,
  alertmsg_WATCHLIST_HIT: d => `Watchlist : ${d.match} (${d.host || d.ip}) — ${d.process || 'processus inconnu'}`,
  time_just_now: "à l'instant",
  time_seconds: n => `il y a ${n}s`,
  time_minutes: n => `il y a ${n}min`,
  time_hours: n => `il y a ${n}h`,

  // Score de confidentialité / Privacy score
  privacy_title: 'Score de confidentialité',
  privacy_critical_label: 'Critique',
  privacy_excellent_label: 'Excellent',
  privacy_risk_factors: n => `${n} facteur${n !== 1 ? 's' : ''} de risque`,
  privacy_more_factors: n => `+${n} autre${n > 1 ? 's' : ''} facteur${n > 1 ? 's' : ''}`,
  privacy_label_excellent: 'Excellent',
  privacy_label_good: 'Bon',
  privacy_label_average: 'Moyen',
  privacy_label_weak: 'Faible',
  privacy_label_critical: 'Critique',

  // Timeline
  timeline_packets: n => `${n.toLocaleString('fr-FR')} paquets`,
  timeline_alerts: n => `${n} alerte${n > 1 ? 's' : ''}`,
  timeline_live: 'Direct',

  // Bascule de capture / Capture toggle
  capture_stop: 'Arrêter',
  capture_start: 'Démarrer',
  capture_stopping: 'Arrêt…',
  capture_starting: 'Démarrage…',

  // Filtre de ports / Port filter
  port_filter: 'Ports',
  port_all: 'Tous les ports',
  port_placeholder: 'Ajouter un port (ex: 443)',
  port_invalid: 'Port invalide',

  // Export
  export_btn: 'Exporter',
  export_graph_json: 'Graphe (JSON)',
  export_graph_csv: 'Graphe (CSV)',
  export_alerts_json: 'Alertes (JSON)',
  export_alerts_csv: 'Alertes (CSV)',

  // Filtre de processus / Process filter
  process_filter: 'Applications',
  process_filter_hint: 'Cliquer pour masquer une app du graphe',
  process_none: 'Aucun processus détecté pour l\'instant',
  process_clear: 'Tout afficher',

  // Liste blanche d'IP / IP whitelist
  ip_whitelist: 'Confiance',
  ip_whitelist_hint: 'Les IP de confiance ne sont plus capturées ni affichées',
  ip_placeholder: 'Ajouter une IP (ex: 1.1.1.1)',
  ip_invalid: 'Adresse IP invalide',
  ip_clear: 'Vider la liste',
  whitelist_action: 'Marquer comme fiable',

  // Carte / Map
  map_you: 'Vous',
  map_located: n => `${n} hôte${n !== 1 ? 's' : ''} localisé${n !== 1 ? 's' : ''}`,
  map_no_geo: 'sans géo',

  // Libellés des facteurs de score / Scoring factor labels
  score_trackers: n => `${n} tracker${n > 1 ? 's' : ''} contacté${n > 1 ? 's' : ''}`,
  score_tracker_traffic: pct => `${pct}% de trafic vers des trackers`,
  score_ad_networks: n => `${n} régie${n > 1 ? 's' : ''} publicitaire${n > 1 ? 's' : ''}`,
  score_beacons: n => `${n} comportement${n > 1 ? 's' : ''} beacon`,
  score_susp_proc: n => `${n} processus suspect${n > 1 ? 's' : ''}`,
  score_susp_ports: n => `${n} port${n > 1 ? 's' : ''} dangereux`,
  score_critical_alerts: n => `${n} alerte${n > 1 ? 's' : ''} critique${n > 1 ? 's' : ''}`,
  score_warnings: n => `${n} alertes`,
  score_https_ratio: pct => `${pct}% de trafic HTTPS`,
  score_no_trackers: 'Aucun tracker détecté',

  // Réglages / Settings
  settings_title: 'Réglages',
  settings_saved: 'Enregistré',
  close: 'Fermer',
  settings_language: 'Langue / Language',
  theme_toggle: 'Thème clair / sombre',
  settings_retention: 'Rétention de l\'historique',
  settings_retention_hint: 'Durée de conservation du trafic et des alertes',
  settings_interface: 'Interface de capture',
  settings_interface_hint: 'Carte réseau écoutée (redémarre la capture)',
  settings_interface_auto: 'Auto (première non-loopback)',
  settings_upload: 'Seuil d\'alerte d\'envoi',
  settings_upload_hint: 'Alerter quand un processus envoie plus que ceci par minute',
  settings_off: 'Désactivé',
  watchlist_title: 'Liste de surveillance',
  watchlist_hint: 'Alerter dès qu\'un trafic touche ces IP ou domaines',
  watchlist_placeholder: '203.0.113.7 ou example.com',
  watchlist_add: 'Ajouter',
  watchlist_remove: 'Retirer',
  update_title: 'Mises à jour',
  update_checking: 'Vérification des mises à jour…',
  update_available: v => `Mise à jour disponible : v${v} — téléchargement`,
  update_downloading: p => `Téléchargement de la mise à jour… ${p}%`,
  update_ready: v => `v${v} téléchargée — redémarrer pour installer`,
  update_none: 'Snitch est à jour',
  update_error: 'Échec de la vérification',
  update_idle: 'Pas encore de vérification',
  update_restart: 'Redémarrer et installer',
  update_check_btn: 'Vérifier',
  update_auto: 'Vérifier automatiquement',
  update_privacy: 'Vérifie github.com pour les nouvelles versions — le seul appel sortant avec le téléchargement GeoIP.',
  geo_title: 'Base de géolocalisation',
  geo_present: dbs => `Installée : ${dbs}`,
  geo_none: 'Non installée — les IP ne sont pas géolocalisées',
  geo_download_btn: 'Télécharger DB-IP Lite (gratuit)',
  geo_consent: 'Télécharge ~50 Mo depuis db-ip.com (CC BY 4.0). C\'est le seul appel sortant possible de Snitch.',
  geo_downloading: 'Téléchargement…',
  geo_done: n => `${n} base(s) téléchargée(s)`,
  geo_failed: 'Échec du téléchargement — vérifiez la connexion',
  diag_title: 'Diagnostic',
  diag_hint: 'Logs et infos système pour les rapports de bug',
  diag_open_logs: 'Logs',
  diag_export: 'Exporter',
  settings_note: 'Tous les réglages sont stockés localement. Snitch n\'envoie rien à des tiers.',
  nav_apps: 'Applications',
  ignore_alert: 'Ignorer ce type/cet hôte',

  // Vue applications / Apps view
  apps_empty: 'Aucun processus attribué pour l\'instant',
  apps_process: 'Processus',
  apps_destinations: 'Hôtes',
  apps_packets: 'Paquets',
  apps_volume: 'Volume',
  apps_top_dest: 'Destinations principales',
  apps_history_60m: 'Dernière heure (octets/min)',
  alertmsg_NEW_HOSTS: n => `${n} nouvel${n > 1 ? 'x' : ''} hôte${n > 1 ? 's' : ''} contacté${n > 1 ? 's' : ''}`,
  settings_autolaunch: 'Lancer à la connexion',
  settings_autolaunch_hint: 'Démarrer Snitch automatiquement à l\'ouverture de session',

  // Premier lancement / Onboarding
  onboard_title: 'Bienvenue dans Snitch',
  onboard_sub: 'Visualiseur de trafic réseau en temps réel — privé par conception.',
  onboard_priv_title: 'Tout reste sur cette machine',
  onboard_priv_body: 'Métadonnées de trafic, alertes et historique sont stockés dans une base SQLite locale. Pas de compte, pas de cloud, pas de télémétrie.',
  onboard_capture_title: 'Ce qui est capturé',
  onboard_capture_body: 'Les en-têtes de paquets seulement : IP de destination, ports, volumes, noms de processus, noms DNS et SNI TLS. Les contenus ne sont jamais lus.',
  onboard_out_title: 'Ce qui quitte la machine',
  onboard_out_body: 'Rien par défaut. Le seul appel sortant possible est le téléchargement de la base de géolocalisation, que vous déclenchez vous-même dans les Réglages.',
  onboard_go: 'Compris',
}

// ── Diccionario español / Spanish dictionary ─────────────────────────────────
// EN: Third UI language — kept structurally identical to `en` so every key
//     resolves; missing keys would fall back to the raw key name.
// FR: Troisième langue d'UI — structure identique à `en` pour que chaque clé
//     se résolve ; une clé absente retomberait sur le nom de clé brut.
const es = {
  // Navegación
  nav_graph: 'Grafo',
  nav_map: 'Mapa',

  // Badge de estado
  status_connected: 'En directo',
  status_connecting: 'Conectando…',
  status_disconnected: 'Desconectado',
  status_error: 'Error',
  lan_devices: n => `${n} dispositivo${n > 1 ? 's' : ''} LAN`,

  // Leyenda
  legend_alert: 'Alerta',
  legend_unknown: 'Desconocido',
  legend_router: 'Router',
  legend_phone: 'Teléfono',
  legend_pc: 'PC',
  legend_iot: 'IoT',
  legend_https: 'HTTPS',
  legend_tracking: 'Rastreo',
  legend_cdn: 'CDN',
  legend_dns: 'DNS',

  // Cabecera + estadísticas de la barra lateral
  app_name: 'SNITCH',
  tagline: 'Vigila cada flujo oculto.',
  footer_credit: 'Desarrollado por aiXis',
  stat_lan: 'Dispositivos LAN',
  stat_ext: 'Hosts ext.',
  stat_traffic: 'Tráfico',

  // Secciones de la barra lateral
  section_lan: n => `Dispositivos LAN (${n})`,
  section_ext: (n, total) => total ? `Hosts externos (${n}/${total})` : `Hosts externos (${n})`,
  section_packets: 'Tráfico reciente',

  // Etiquetas de los campos de detalle de nodo
  field_ip: 'IP',
  field_mac: 'MAC',
  field_hostname: 'Nombre de host',
  field_vendor: 'Fabricante',
  field_type: 'Tipo',
  field_country: 'País',
  field_city: 'Ciudad',
  field_org: 'Org',
  field_category: 'Categoría',
  field_traffic: 'Tráfico',
  field_packets: 'Paquetes',
  processes: 'Procesos',
  online: 'en línea',
  offline: 'fuera de línea',

  // Búsqueda
  search_placeholder: 'Buscar host, IP, país…',
  cat_all: 'Todo',
  cat_unknown: 'Desconocido',
  cat_alerted: 'Alertas',
  cat_safe: 'Seguro',
  cat_tracking: 'Rastreo',
  cat_cdn: 'CDN',
  cat_dns: 'DNS',
  cat_admin: 'Admin',
  cat_local: 'Local',
  cat_lan_device: 'Dispositivo LAN',
  cat_other: 'Otro',

  node_local: 'Este dispositivo',
  hint_local: 'Esta es ESTA máquina — la que ejecuta Snitch. Todo lo que envía o recibe irradia desde el centro del grafo.',
  unidentified: 'sin identificar',
  devtype_router: 'Router',
  devtype_phone: 'Teléfono',
  devtype_pc: 'Ordenador',
  devtype_tv: 'TV',
  devtype_iot: 'Dispositivo IoT',
  devtype_unknown: 'Tipo desconocido',
  hint_unidentified: 'Aún no identificado — su nombre aparece cuando se anuncia (DNS/mDNS) o se conoce el fabricante de su MAC. Si no lo reconoces, revisa la lista de clientes de tu router.',
  hint_unresolved: 'Aún sin nombre — el dominio aparece cuando una respuesta DNS o un handshake TLS lo revela.',
  hint_private_mac: 'Dirección MAC privada (aleatorizada) — iOS/Android/Windows ocultan la real, así que el fabricante no se puede identificar. Es un comportamiento de privacidad normal.',
  hint_gateway: 'Esta es tu caja/router de internet — TODO tu tráfico pasa físicamente por él, así que verlo comunicar es normal y esperado.',
  hint_lan_idle: 'Visto en tu red vía la tabla de vecinos — sin datos intercambiados. Una arista discontinua significa « presente », no « hablando ».',
  hint_lan_active: b => `${b} intercambiados — normalmente anuncios automáticos (Bonjour/mDNS, compartición de archivos). Vigílalo si el volumen sube.`,
  ext_empty: 'Sin conexiones externas todavía — todo lo que hable tu máquina aparecerá aquí.',
  legend_edge_solid: 'línea sólida = tráfico',
  legend_edge_dashed: 'discontinua = visto, sin datos',
  legend_ring_safe: 'anillo verde = identificado, seguro',
  legend_ring_warn: 'anillo ámbar = sospechoso',
  legend_ring_crit: 'anillo rojo = alerta',
  legend_ring_none: 'sin anillo = no identificado, neutro',
  legend_perimeter: 'Perímetro LAN',
  perim_lan: 'RED LOCAL',

  // Panel de alertas
  alerts_title: 'Alertas',
  alerts_total: 'total',
  alerts_empty: 'Sin alertas por ahora',
  alert_NEW_HOST: 'Host nuevo',
  alert_SUSPICIOUS_PROCESS: 'Proceso sospechoso',
  alert_SUSPICIOUS_PORT: 'Puerto sospechoso',
  alert_BEACON: 'Beacon C2',
  alert_VOLUME_SPIKE: 'Pico de tráfico',
  alert_NEW_LAN_DEVICE: 'Dispositivo nuevo',
  alert_DEVICE_OFFLINE: 'Dispositivo fuera de línea',
  alert_MEDIA_EXFIL: 'Exfiltración de medios',
  alert_PORT_SCAN: 'Escaneo de puertos',
  alert_UPLOAD_SPIKE: 'Pico de subida',
  alert_WATCHLIST_HIT: 'Coincidencia watchlist',
  alertmsg_NEW_HOST: d => `Host nuevo contactado: ${d.host || d.ip}`,
  alertmsg_SUSPICIOUS_PROCESS: d => `Proceso sospechoso: ${d.process} → ${d.host || d.ip}`,
  alertmsg_SUSPICIOUS_PORT: d => `Puerto sospechoso ${d.port} (${d.reason}) → ${d.host || d.ip}`,
  alertmsg_BEACON: d => `Regularidad tipo beacon: intervalo ~${d.interval_s}s hacia ${d.host || d.ip}`,
  alertmsg_VOLUME_SPIKE: d => `Pico de datos hacia ${d.host || d.ip}: ${Math.round((d.bytes || 0) / 1024)} KB en ${d.window_s}s`,
  alertmsg_MEDIA_EXFIL: d => `Posible exfiltración de ${d.device === 'camera' ? 'cámara' : 'micrófono'}: ${d.process} → ${d.host || d.ip}`,
  alertmsg_NEW_LAN_DEVICE: d => `Nuevo dispositivo en la red: ${d.host || d.ip}`,
  alertmsg_DEVICE_OFFLINE: d => `Dispositivo desconectado: ${d.host || d.ip}`,
  alertmsg_PORT_SCAN: d => `Escaneo de puertos: ${d.source || d.ip} tocó ${d.ports}+ puertos en ${d.window_s}s`,
  alertmsg_UPLOAD_SPIKE: d => `Pico de subida: ${d.process} envió ${d.mb} MB en ${d.window_s}s`,
  alertmsg_WATCHLIST_HIT: d => `Watchlist: ${d.match} (${d.host || d.ip}) — ${d.process || 'proceso desconocido'}`,
  time_just_now: 'ahora mismo',
  time_seconds: n => `hace ${n}s`,
  time_minutes: n => `hace ${n}min`,
  time_hours: n => `hace ${n}h`,

  // Puntuación de privacidad
  privacy_title: 'Puntuación de privacidad',
  privacy_critical_label: 'Crítica',
  privacy_excellent_label: 'Excelente',
  privacy_risk_factors: n => `${n} factor${n !== 1 ? 'es' : ''} de riesgo`,
  privacy_more_factors: n => `+${n} factor${n > 1 ? 'es' : ''} más`,
  privacy_label_excellent: 'Excelente',
  privacy_label_good: 'Buena',
  privacy_label_average: 'Media',
  privacy_label_weak: 'Débil',
  privacy_label_critical: 'Crítica',

  // Timeline
  timeline_packets: n => `${n.toLocaleString()} paquetes`,
  timeline_alerts: n => `${n} alerta${n > 1 ? 's' : ''}`,
  timeline_live: 'En directo',

  // Botón de captura
  capture_stop: 'Detener',
  capture_start: 'Iniciar',
  capture_stopping: 'Deteniendo…',
  capture_starting: 'Iniciando…',

  // Filtro de puertos
  port_filter: 'Puertos',
  port_all: 'Todos los puertos',
  port_placeholder: 'Añadir puerto (ej. 443)',
  port_invalid: 'Puerto inválido',

  // Exportar
  export_btn: 'Exportar',
  export_graph_json: 'Grafo (JSON)',
  export_graph_csv: 'Grafo (CSV)',
  export_alerts_json: 'Alertas (JSON)',
  export_alerts_csv: 'Alertas (CSV)',

  // Filtro de procesos
  process_filter: 'Apps',
  process_filter_hint: 'Clic para ocultar la app del grafo',
  process_none: 'Sin procesos detectados aún',
  process_clear: 'Mostrar todas las apps',

  // Lista blanca de IP
  ip_whitelist: 'De confianza',
  ip_whitelist_hint: 'Las IP de confianza ya no se capturan ni se muestran',
  ip_placeholder: 'Añadir IP (ej. 1.1.1.1)',
  ip_invalid: 'Dirección IP inválida',
  ip_clear: 'Vaciar la lista',
  whitelist_action: 'Marcar como de confianza',

  // Mapa
  map_you: 'Tú',
  map_located: n => `${n} host${n !== 1 ? 's' : ''} localizado${n !== 1 ? 's' : ''}`,
  map_no_geo: 'sin geo',

  // Factores de la puntuación
  score_trackers: n => `${n} rastreador${n > 1 ? 'es' : ''} contactado${n > 1 ? 's' : ''}`,
  score_tracker_traffic: pct => `${pct}% del tráfico hacia rastreadores`,
  score_ad_networks: n => `${n} red${n > 1 ? 'es' : ''} publicitaria${n > 1 ? 's' : ''}`,
  score_beacons: n => `${n} comportamiento${n > 1 ? 's' : ''} tipo beacon`,
  score_susp_proc: n => `${n} proceso${n > 1 ? 's' : ''} sospechoso${n > 1 ? 's' : ''}`,
  score_susp_ports: n => `${n} puerto${n > 1 ? 's' : ''} peligroso${n > 1 ? 's' : ''}`,
  score_critical_alerts: n => `${n} alerta${n > 1 ? 's' : ''} crítica${n > 1 ? 's' : ''}`,
  score_warnings: n => `${n} avisos`,
  score_https_ratio: pct => `${pct}% de tráfico HTTPS`,
  score_no_trackers: 'Sin rastreadores detectados',

  // Ajustes
  settings_title: 'Ajustes',
  settings_saved: 'Guardado',
  close: 'Cerrar',
  settings_language: 'Idioma / Language',
  theme_toggle: 'Tema claro / oscuro',
  settings_retention: 'Retención del historial',
  settings_retention_hint: 'Cuánto tiempo se conserva el tráfico y las alertas',
  settings_interface: 'Interfaz de captura',
  settings_interface_hint: 'Qué adaptador de red se escucha (reinicia la captura)',
  settings_interface_auto: 'Auto (primera no-loopback)',
  settings_upload: 'Umbral de alerta de subida',
  settings_upload_hint: 'Avisar cuando un proceso suba más de esto por minuto',
  settings_off: 'Desactivado',
  watchlist_title: 'Lista de vigilancia',
  watchlist_hint: 'Alertar en cuanto el tráfico toque estas IP o dominios',
  watchlist_placeholder: '203.0.113.7 o example.com',
  watchlist_add: 'Añadir',
  watchlist_remove: 'Quitar',
  update_title: 'Actualizaciones',
  update_checking: 'Buscando actualizaciones…',
  update_available: v => `Actualización disponible: v${v} — descargando`,
  update_downloading: p => `Descargando actualización… ${p}%`,
  update_ready: v => `v${v} descargada — reiniciar para instalar`,
  update_none: 'Snitch está al día',
  update_error: 'Falló la comprobación',
  update_idle: 'Sin comprobación todavía',
  update_restart: 'Reiniciar e instalar',
  update_check_btn: 'Comprobar ahora',
  update_auto: 'Comprobar automáticamente',
  update_privacy: 'Consulta github.com para nuevas versiones — la única llamada saliente junto a la descarga GeoIP.',
  geo_title: 'Base de geolocalización',
  geo_present: dbs => `Instalada: ${dbs}`,
  geo_none: 'No instalada — las IP no se geolocalizan',
  geo_download_btn: 'Descargar DB-IP Lite (gratis)',
  geo_consent: 'Descarga ~50 MB de db-ip.com (CC BY 4.0). Es la única llamada saliente posible de Snitch.',
  geo_downloading: 'Descargando…',
  geo_done: n => `${n} base(s) descargada(s)`,
  geo_failed: 'Descarga fallida — revisa tu conexión',
  diag_title: 'Diagnóstico',
  diag_hint: 'Logs e info del sistema para informes de error',
  diag_open_logs: 'Logs',
  diag_export: 'Exportar',
  settings_note: 'Todos los ajustes se guardan localmente. Snitch no envía nada a terceros.',
  nav_apps: 'Aplicaciones',
  ignore_alert: 'Ignorar este tipo/este host',

  // Vista de aplicaciones
  apps_empty: 'Sin procesos atribuidos todavía',
  apps_process: 'Proceso',
  apps_destinations: 'Hosts',
  apps_packets: 'Paquetes',
  apps_volume: 'Volumen',
  apps_top_dest: 'Destinos principales',
  apps_history_60m: 'Última hora (bytes/min)',
  alertmsg_NEW_HOSTS: n => `${n} host${n > 1 ? 's' : ''} nuevo${n > 1 ? 's' : ''} contactado${n > 1 ? 's' : ''}`,
  settings_autolaunch: 'Iniciar al arrancar',
  settings_autolaunch_hint: 'Arrancar Snitch automáticamente al iniciar sesión',

  // Onboarding
  onboard_title: 'Bienvenido a Snitch',
  onboard_sub: 'Visualizador de tráfico de red en tiempo real — privado por diseño.',
  onboard_priv_title: 'Todo se queda en esta máquina',
  onboard_priv_body: 'Metadatos de tráfico, alertas e historial se guardan en una base SQLite local. Sin cuenta, sin nube, sin telemetría.',
  onboard_capture_title: 'Qué se captura',
  onboard_capture_body: 'Solo cabeceras de paquetes: IP de destino, puertos, volúmenes, nombres de proceso, nombres DNS y SNI TLS. Los contenidos nunca se leen.',
  onboard_out_title: 'Qué sale de la máquina',
  onboard_out_body: 'Nada por defecto. La única llamada saliente posible es la descarga de la base de geolocalización, que tú mismo lanzas en Ajustes.',
  onboard_go: 'Entendido',
}

// ── Context / Contexte ───────────────────────────────────────────────────────
const I18nContext = createContext(null)

/**
 * EN: Provides { lang, t, setLang } to the whole tree. `t(key, ...args)`
 *     resolves a dictionary entry — functions are called with args, strings
 *     returned as-is, missing keys fall back to the key itself.
 * FR: Fournit { lang, t, setLang } à tout l'arbre. `t(key, ...args)` résout une
 *     entrée du dictionnaire — les fonctions sont appelées avec args, les
 *     chaînes renvoyées telles quelles, les clés manquantes retombent sur la clé.
 */
export function I18nProvider({ children }) {
  // EN: Persisted language — survives restarts (localStorage, not just RAM).
  // FR: Langue persistée — survit aux redémarrages (localStorage, pas juste la RAM).
  const [lang, setLangState] = useState(
    () => localStorage.getItem('snitch_lang') || 'en')
  const setLang = (l) => {
    localStorage.setItem('snitch_lang', l)
    setLangState(l)
  }
  const dict = { en, fr, es }[lang] || en

  function t(key, ...args) {
    // EN: Own-property check — without it, keys like "constructor" would
    //     resolve to inherited Object members (which are callable).
    // FR: Vérification de propriété propre — sans elle, des clés comme
    //     « constructor » résoudraient vers les membres hérités d'Object
    //     (qui sont appelables).
    if (!Object.hasOwn(dict, key)) return key
    const val = dict[key]
    if (typeof val === 'function') return val(...args)
    return val
  }

  return (
    <I18nContext.Provider value={{ lang, t, setLang }}>
      {children}
    </I18nContext.Provider>
  )
}

export const useT = () => useContext(I18nContext)
