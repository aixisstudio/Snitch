/**
 * Snitch — WebSocket hook.
 *
 * EN: Single source of truth for realtime state. Maintains the node/edge/LAN
 *     device maps, the recent-packet list, alerts, capture status and the
 *     per-second bandwidth buckets that feed the sparkline.
 *
 *     Reconnection: exponential backoff (1 s → 2 s → 4 s … capped at 30 s)
 *     instead of a fixed 2 s — a dead backend no longer gets hammered. The
 *     pending retry timer IS cleared on unmount (the old version leaked it).
 *     The connection is opened with the API token via wsUrlWithToken().
 *
 * FR: Source de vérité unique pour l'état temps réel. Maintient les tables de
 *     nœuds/arêtes/appareils LAN, la liste des paquets récents, les alertes,
 *     le statut de capture et les seaux de débit par seconde qui alimentent la
 *     sparkline.
 *
 *     Reconnexion : backoff exponentiel (1 s → 2 s → 4 s … plafonné à 30 s)
 *     au lieu de 2 s fixes — un backend mort n'est plus martelé. Le timer de
 *     réessai EST nettoyé au démontage (l'ancienne version le fuyait).
 *     La connexion s'ouvre avec le jeton API via wsUrlWithToken().
 */
import { useEffect, useRef, useState } from 'react'
import { API_BASE, authHeaders, wsUrlWithToken } from '../api'

export function useWebSocket(url) {
  const ws = useRef(null)
  const [nodes, setNodes] = useState({})
  const [edges, setEdges] = useState({})
  const [lanDevices, setLanDevices] = useState({})
  const [packets, setPackets] = useState([])
  const [alerts, setAlerts] = useState([])
  const [unread, setUnread] = useState(0)
  const [status, setStatus] = useState('connecting')
  const [bandwidth, setBandwidth] = useState([])
  const [capturing, setCapturing] = useState(true)
  const [portFilter, setPortFilter] = useState([])
  const [excludedProcesses, setExcludedProcesses] = useState([])
  const [whitelistedIps, setWhitelistedIps] = useState([])
  const [media, setMedia] = useState({ mic: [], camera: [] })
  // EN: { secondTimestamp: bytesReceivedThatSecond } — rolled into `bandwidth`.
  // FR: { timestampSeconde: octetsReçusCetteSeconde } — agrégé dans `bandwidth`.
  const bwRef = useRef({})

  // EN: Every second, fold the byte buckets into the `bandwidth` array and
  //     drop buckets older than ~61 s.
  // FR: Chaque seconde, transformer les seaux d'octets en tableau `bandwidth`
  //     et jeter les seaux de plus de ~61 s.
  useEffect(() => {
    const id = setInterval(() => {
      const now = Date.now()
      const cutoff = now - 61000
      Object.keys(bwRef.current).forEach(k => {
        if (+k < cutoff) delete bwRef.current[k]
      })
      const arr = Object.entries(bwRef.current)
        .map(([ts, bps]) => ({ ts: +ts, bps }))
        .sort((a, b) => a.ts - b.ts)
      setBandwidth(arr)
    }, 1000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    let stopped = false
    let attempts = 0
    let timer = null

    async function connect() {
      // EN: Resolve the token BEFORE opening the socket.
      // FR: Résoudre le jeton AVANT d'ouvrir le socket.
      const wsUrl = await wsUrlWithToken(url)
      if (stopped) return

      ws.current = new WebSocket(wsUrl)

      ws.current.onopen = () => {
        attempts = 0
        setStatus('connected')
      }
      ws.current.onclose = () => {
        if (stopped) return
        setStatus('disconnected')
        // EN: Exponential backoff — 1s, 2s, 4s … max 30s.
        // FR: Backoff exponentiel — 1s, 2s, 4s … max 30s.
        const delay = Math.min(30000, 1000 * 2 ** attempts)
        attempts += 1
        timer = setTimeout(connect, delay)
      }
      ws.current.onerror = () => setStatus('error')

      ws.current.onmessage = (evt) => {
        const msg = JSON.parse(evt.data)

        // EN: Initial snapshot — replaces all local state.
        // FR: Instantané initial — remplace tout l'état local.
        if (msg.type === 'init') {
          if (msg.media) setMedia(msg.media)
          if (msg.capturing !== undefined) setCapturing(msg.capturing)
          if (msg.ports !== undefined) setPortFilter(msg.ports)
          if (msg.excluded_processes !== undefined) setExcludedProcesses(msg.excluded_processes)
          if (msg.whitelisted_ips !== undefined) setWhitelistedIps(msg.whitelisted_ips)
          const nodeMap = {}, edgeMap = {}, deviceMap = {}
          msg.nodes.forEach(n => {
            if (n.category === 'lan_device') deviceMap[n.id] = n
            else nodeMap[n.id] = n
          })
          msg.edges.forEach(e => { edgeMap[e.id] = e })
          setNodes(nodeMap)
          setEdges(edgeMap)
          setLanDevices(deviceMap)
          if (msg.alerts?.length) setAlerts(msg.alerts.reverse())
        }

        // EN: Incremental graph update (one per packet).
        // FR: Mise à jour incrémentale du graphe (une par paquet).
        if (msg.type === 'update') {
          setNodes(prev => ({ ...prev, [msg.node.id]: msg.node }))
          setEdges(prev => ({ ...prev, [msg.edge.id]: msg.edge }))
          setPackets(prev => [msg.packet, ...prev].slice(0, 100))
          // EN: Accumulate bytes into the current second bucket.
          // FR: Accumuler les octets dans le seau de la seconde courante.
          const sec = Math.floor(Date.now() / 1000) * 1000
          bwRef.current[sec] = (bwRef.current[sec] || 0) + (msg.packet?.size || 0)
        }

        // EN: LAN device appeared / changed / went offline.
        // FR: Appareil LAN apparu / modifié / passé hors ligne.
        if (msg.type === 'device_update') {
          setLanDevices(prev => ({ ...prev, [msg.device.id]: msg.device }))
          if (msg.edge) setEdges(prev => ({ ...prev, [msg.edge.id]: msg.edge }))
        }

        if (msg.type === 'alert') {
          setAlerts(prev => [msg.alert, ...prev].slice(0, 200))
          setUnread(prev => prev + 1)
        }

        // EN: Capture/filter status changed (local or remote action).
        // FR: Le statut capture/filtres a changé (action locale ou distante).
        if (msg.type === 'capture_status') {
          setCapturing(msg.capturing)
          if (msg.ports !== undefined) setPortFilter(msg.ports)
          if (msg.excluded_processes !== undefined) setExcludedProcesses(msg.excluded_processes)
          if (msg.whitelisted_ips !== undefined) setWhitelistedIps(msg.whitelisted_ips)
        }

        // EN: Whitelisted nodes were removed server-side — mirror the removal.
        // FR: Des nœuds whitelistés ont été retirés côté serveur — refléter la suppression.
        if (msg.type === 'nodes_removed') {
          const removed = new Set(msg.ids || [])
          setNodes(prev => {
            const out = {}
            for (const [id, n] of Object.entries(prev)) if (!removed.has(id)) out[id] = n
            return out
          })
          setEdges(prev => {
            const out = {}
            for (const [id, e] of Object.entries(prev)) if (!removed.has(e.source) && !removed.has(e.target)) out[id] = e
            return out
          })
        }

        // EN: Mic/camera usage changed. / FR: L'usage micro/caméra a changé.
        if (msg.type === 'media') {
          setMedia({ mic: msg.mic || [], camera: msg.camera || [] })
        }

        // EN: Full graph reset (e.g. after the port filter changed).
        // FR: Réinitialisation complète du graphe (ex. après changement du filtre de ports).
        if (msg.type === 'reset') {
          const nodeMap = {}, deviceMap = {}
          ;(msg.nodes || []).forEach(n => {
            if (n.category === 'lan_device') deviceMap[n.id] = n
            else nodeMap[n.id] = n
          })
          const edgeMap = {}
          ;(msg.edges || []).forEach(e => { edgeMap[e.id] = e })
          setNodes(nodeMap)
          setEdges(edgeMap)
          setLanDevices(deviceMap)
          setPackets([])
          if (msg.ports !== undefined) setPortFilter(msg.ports)
        }
      }
    }

    connect()
    return () => {
      // EN: Stop reconnecting and free the pending timer on unmount.
      // FR: Arrêter les reconnexions et libérer le timer en attente au démontage.
      stopped = true
      if (timer) clearTimeout(timer)
      ws.current?.close()
    }
  }, [url])

  const clearUnread = () => setUnread(0)

  // ── REST control actions / Actions de contrôle REST ────────────────────────

  async function toggleCapture() {
    const endpoint = capturing ? '/capture/stop' : '/capture/start'
    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: await authHeaders(),
    })
    const data = await res.json()
    setCapturing(data.capturing)
  }

  async function updatePortFilter(ports) {
    const res = await fetch(`${API_BASE}/capture/ports`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ ports }),
    })
    const data = await res.json()
    setPortFilter(data.ports)
  }

  async function updateProcessFilter(excluded) {
    const res = await fetch(`${API_BASE}/capture/processes`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ excluded }),
    })
    const data = await res.json()
    setExcludedProcesses(data.excluded_processes)
  }

  async function updateIpWhitelist(ips) {
    const res = await fetch(`${API_BASE}/capture/whitelist`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ ips }),
    })
    const data = await res.json()
    setWhitelistedIps(data.whitelisted_ips)
  }

  return { nodes, edges, lanDevices, packets, alerts, unread, clearUnread, status, bandwidth, capturing, toggleCapture, portFilter, updatePortFilter, excludedProcesses, updateProcessFilter, whitelistedIps, updateIpWhitelist, media }
}
