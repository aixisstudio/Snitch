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
  tagline: "Know who's talking.",
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
}

// ── Dictionnaire français / French dictionary ────────────────────────────────
const fr = {
  // Navigation
  nav_graph: 'Graphe',
  nav_map: 'Carte',

  // Badge de statut / Status badge
  status_connected: 'Live',
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
  legend_tracking: 'Tracking',
  legend_cdn: 'CDN',
  legend_dns: 'DNS',

  // En-tête de barre latérale + stats / Sidebar header + stats
  app_name: 'SNITCH',
  tagline: 'Sache qui parle.',
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
  alertmsg_NEW_HOST: d => `Nouvel hôte contacté : ${d.host || d.ip}`,
  alertmsg_SUSPICIOUS_PROCESS: d => `Processus suspect : ${d.process} → ${d.host || d.ip}`,
  alertmsg_SUSPICIOUS_PORT: d => `Port suspect ${d.port} (${d.reason}) → ${d.host || d.ip}`,
  alertmsg_BEACON: d => `Régularité type beacon : intervalle ~${d.interval_s}s vers ${d.host || d.ip}`,
  alertmsg_VOLUME_SPIKE: d => `Pic de données vers ${d.host || d.ip} : ${Math.round((d.bytes || 0) / 1024)} Ko en ${d.window_s}s`,
  alertmsg_PORT_SCAN: d => `Scan de ports : ${d.source || d.ip} a touché ${d.ports}+ ports en ${d.window_s}s`,
  alertmsg_MEDIA_EXFIL: d => `Exfiltration ${d.device === 'camera' ? 'caméra' : 'micro'} suspectée : ${d.process} → ${d.host || d.ip}`,
  alertmsg_NEW_LAN_DEVICE: d => `Nouvel appareil sur le réseau : ${d.host || d.ip}`,
  alertmsg_DEVICE_OFFLINE: d => `Appareil hors ligne : ${d.host || d.ip}`,
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
  privacy_label_excellent: 'Excellente',
  privacy_label_good: 'Bonne',
  privacy_label_average: 'Moyenne',
  privacy_label_weak: 'Faible',
  privacy_label_critical: 'Critique',

  // Timeline
  timeline_packets: n => `${n.toLocaleString('fr-FR')} paquets`,
  timeline_alerts: n => `${n} alerte${n > 1 ? 's' : ''}`,
  timeline_live: 'Direct',

  // Bascule de capture / Capture toggle
  capture_stop: 'Stop',
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
  process_filter: 'Apps',
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
  const dict = lang === 'fr' ? fr : en

  function t(key, ...args) {
    const val = dict[key]
    if (val === undefined) return key
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
