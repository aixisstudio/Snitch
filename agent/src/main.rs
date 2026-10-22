//! Snitch agent — lightweight remote sensor for a Snitch collector.
//! Agent Snitch — capteur léger pour un collecteur Snitch.
//!
//! EN: Watches the host's live socket table (Linux: /proc/net/{tcp,tcp6,
//!     udp,udp6}; falls back to a periodic scan) and pushes the DIFF —
//!     new outbound/established endpoints only — to the collector's
//!     `POST /ingest/events` endpoint, contract `snitch-agent/1`.
//!
//!     Deliberately minimal-dependency and honest about scope:
//!       * it observes SOCKETS, it does not sniff packets — no payloads,
//!         no SNI, no DNS answers (the collector's own pcap path keeps
//!         those duties on the host it runs on);
//!       * pid↔process attribution walks /proc/*/fd (Linux; other OSes
//!         report pid 0 honestly);
//!       * transport is plain HTTP by default — set SNITCH_TLS=1 for
//!         rustls TLS (system-free pure-Rust stack). On hostile links
//!         either enable it or run behind WireGuard/Tailscale.
//!
//!     Config: SNITCH_SERVER="collector:8000"  SNITCH_TOKEN="<bearer>"
//!             SNITCH_HOST="agent-name"        SNITCH_INTERVAL_SECS=5
//!             SNITCH_TLS=1                    SNITCH_CA="/path/ca.pem"
//!
//! FR: Surveille la table de sockets de l'hôte (/proc/net/*) et pousse
//!     le DIFF — nouvelles extrémités sortantes/établies — vers le
//!     collecteur `POST /ingest/events`, contrat `snitch-agent/1`.
//!     Zéro dépendance volontaire, périmètre honnête : SOCKETS seulement
//!     (pas de payloads/SNI/DNS), attribution pid↔process en TODO, HTTP
//!     uniquement (domaine de confiance LAN).

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::process;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AGENT_ID: &str = "snitch-agent/1";
const MAX_EVENTS_PER_POST: usize = 1000; // EN: matches backend cap / FR: cap backend

/// EN: Transport abstraction — plain TCP or a rustls TLS session over it.
///     Both implement Read+Write so post_batch stays transport-agnostic.
/// FR: Abstraction de transport — TCP brut ou session TLS rustls par-dessus.
///     Les deux implémentent Read+Write pour que post_batch reste agnostique.
enum Transport {
    Plain(TcpStream),
    Tls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

/// EN: Build the root store — the system-free webpki bundle by default,
///     plus an optional extra CA PEM (SNITCH_CA) for internal collectors
///     terminating TLS with a private/self-signed certificate.
/// FR: Construire le magasin de racines — le bundle webpki autonome par
///     défaut, plus une CA PEM optionnelle (SNITCH_CA) pour les collecteurs
///     internes terminant TLS avec un certificat privé/auto-signé.
fn root_store(ca_path: Option<&str>) -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_path {
        let f = fs::File::open(path).map_err(|e| format!("open CA {path}: {e}"))?;
        let certs = rustls_pemfile::certs(&mut BufReader::new(f))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse CA {path}: {e}"))?;
        if certs.is_empty() {
            return Err(format!("no PEM certificates in {path}"));
        }
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(format!("CA file {path} added 0 usable roots"));
        }
    }
    Ok(roots)
}

fn connect(server: &str, use_tls: bool, ca_path: Option<&str>)
           -> Result<Transport, String> {
    let stream = TcpStream::connect(server)
        .map_err(|e| format!("connect {server}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    if !use_tls {
        return Ok(Transport::Plain(stream));
    }
    // EN: SNI / verification name = the host part of "host:port".
    // FR: Nom SNI / de vérification = la partie hôte de « host:port ».
    let host = server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server);
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("bad server name {host}: {e}"))?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store(ca_path)?)
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| format!("tls init: {e}"))?;
    Ok(Transport::Tls(rustls::StreamOwned::new(conn, stream)))
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Sock {
    proto: String,      // "tcp" | "udp"
    local: String,      // "ip:port"
    remote: String,     // "ip:port" — empty when LISTEN/unconnected
    state: u8,
    inode: u64,         // EN: socket inode → pid attribution key / FR: inode → clé d'attribution
}

fn hex_ip(h: &str, v6: bool) -> String {
    // EN: /proc stores addresses little-endian hex. IPv4: 8 chars.
    //     IPv6: 32 chars in 4 little-endian u32 groups.
    // FR: /proc stocke les adresses en hexa little-endian.
    if !v6 {
        let b: Vec<u8> = (0..4)
            .filter_map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok())
            .collect();
        if b.len() == 4 {
            return format!("{}.{}.{}.{}", b[3], b[2], b[1], b[0]);
        }
        return String::new();
    }
    if h.len() != 32 {
        return String::new();
    }
    let mut b = [0u8; 16];
    for i in 0..16 {
        b[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    // EN: each 4-byte group is little-endian — swap inside each group.
    // FR: chaque groupe de 4 octets est little-endian — swap par groupe.
    for g in 0..4 {
        b.swap(g * 4, g * 4 + 3);
        b.swap(g * 4 + 1, g * 4 + 2);
    }
    let a = std::net::Ipv6Addr::from(b);
    a.to_string()
}

fn parse_lines(text: &str, proto: &str, v6: bool, out: &mut HashSet<Sock>) {
    // EN: One line: sl local rem st tx rx tr when retrnsmt uid timeout inode
    //     — rem "00000000:0000" = unconnected; f[9] = socket inode.
    // FR: Une ligne : sl local rem st … — rem « 00000000:0000 » = non
    //     connecté ; f[9] = inode du socket.
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (lip, lport) = f[1].split_once(':').unwrap_or(("", "0"));
        let (rip, rport) = f[2].split_once(':').unwrap_or(("", "0"));
        let port = u16::from_str_radix(rport, 16).unwrap_or(0);
        let state = u8::from_str_radix(f[3], 16).unwrap_or(0);
        if port == 0 {
            continue; // EN: LISTEN/unnamed — not an outbound flow / FR: pas un flux sortant
        }
        let local = format!("{}:{}", hex_ip(lip, v6),
                            u16::from_str_radix(lport, 16).unwrap_or(0));
        let remote = format!("{}:{}", hex_ip(rip, v6), port);
        out.insert(Sock { proto: proto.into(), local, remote, state,
                          inode: f[9].parse().unwrap_or(0) });
    }
}

fn parse_table(path: &str, proto: &str, v6: bool, out: &mut HashSet<Sock>) {
    if let Ok(text) = fs::read_to_string(path) {
        parse_lines(&text, proto, v6, out);
    }
}

fn socket_table() -> HashSet<Sock> {
    let mut s = HashSet::with_capacity(4096);
    for (path, proto, v6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp", true),
    ] {
        parse_table(path, proto, v6, &mut s);
    }
    s
}

fn json_escape(s: &str) -> String {
    s.chars().flat_map(|c| match c {
        '"' => vec!['\\', '"'],
        '\\' => vec!['\\', '\\'],
        c if (c as u32) < 0x20 => {
            format!("\\u{:04x}", c as u32).chars().collect()
        }
        c => vec![c],
    }).collect()
}

fn post_batch(server: &str, token: &str, host: &str,
              events: &[String], use_tls: bool, ca_path: Option<&str>)
              -> Result<(), String> {
    // EN: Minimal HTTP/1.1 POST over plain TCP or rustls TLS. `sagt_…`
    //     tokens are per-agent enrolled credentials → `X-Snitch-Agent`;
    //     anything else is the master API token → `X-Snitch-Token`.
    // FR: POST HTTP/1.1 minimal sur TCP brut ou TLS rustls. Les jetons
    //     « sagt_… » sont des crédences d'agent enrôlé → « X-Snitch-Agent » ;
    //     le reste = jeton maître → « X-Snitch-Token ».
    let auth = if token.starts_with("sagt_") {
        format!("X-Snitch-Agent: {token}")
    } else {
        format!("X-Snitch-Token: {token}")
    };
    let body = format!(
        "{{\"agent\":\"{}\",\"host\":\"{}\",\"events\":[{}]}}",
        json_escape(AGENT_ID), json_escape(host), events.join(","));
    let req = format!(
        "POST /ingest/events HTTP/1.1\r\nHost: {server}\r\n\
         {auth}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len());
    let mut stream = connect(server, use_tls, ca_path)?;
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    // EN: read the whole response; a TLS peer that drops without
    //     close_notify must not discard an otherwise complete answer —
    //     only propagate the error when nothing arrived at all.
    // FR: lire toute la réponse ; un pair TLS qui coupe sans close_notify
    //     ne doit pas faire perdre une réponse complète — ne propager
    //     l'erreur que si rien n'est arrivé.
    let mut raw = Vec::new();
    let read_res = stream.read_to_end(&mut raw);
    if raw.is_empty() {
        read_res.map_err(|e| e.to_string())?;
    }
    let resp = String::from_utf8_lossy(&raw);
    match resp.split(' ').nth(1) {
        Some(code) if code.starts_with('2') => Ok(()),
        _ => Err(format!("ingest rejected: {}",
                         resp.lines().next().unwrap_or("?"))),
    }
}

/// EN: socket inode → (pid, process name), built by walking
///     /proc/<pid>/fd symlink targets "socket:[inode]" — the same
///     technique netstat/ss use, pure std, Linux-only. Built lazily:
///     only when a diff produced new sockets to attribute.
/// FR: inode de socket → (pid, nom du processus), construit en lisant
///     les liens /proc/<pid>/fd « socket:[inode] » — même technique que
///     netstat/ss, std pur, Linux seulement. Construit à la demande.
fn inode_pid_map() -> std::collections::HashMap<u64, (u32, String)> {
    let mut m = std::collections::HashMap::new();
    let Ok(procs) = fs::read_dir("/proc") else { return m };
    for entry in procs.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else { continue };
        let comm = || -> String {
            fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap_or_default().trim().to_string()
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else { continue };
            let t = target.to_string_lossy();
            if let Some(inner) = t.strip_prefix("socket:[")
                                   .and_then(|s| s.strip_suffix(']')) {
                if let Ok(ino) = inner.parse::<u64>() {
                    m.entry(ino).or_insert_with(|| (pid, comm()));
                }
            }
        }
    }
    m
}

fn sock_to_event(s: &Sock,
                 pids: &std::collections::HashMap<u64, (u32, String)>)
                 -> Option<String> {
    // EN: only flow-like rows — a REMOTE endpoint with a real port.
    //     Direction is "out": the agent reports what the box reaches,
    //     which is the threat surface Snitch models.
    // FR: seulement les lignes flux — une extrémité distante avec un vrai
    //     port. Direction « out » : l'agent rapporte ce que la machine
    //     joint, surface de menace modélisée par Snitch.
    let (rip, rport) = s.remote.rsplit_once(':')?;
    let (lip, lport) = s.local.rsplit_once(':')?;
    if rip.is_empty() || rip == "0.0.0.0" || rip == "::" || rport == "0" {
        return None;
    }
    let (pid, pname) = pids.get(&s.inode)
        .map(|(p, n)| (*p, n.clone()))
        .unwrap_or((0, String::new()));
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!(
        "{{\"ts\":{ts},\"src_ip\":\"{}\",\"dst_ip\":\"{}\",\
         \"src_port\":{},\"dst_port\":{},\"proto\":\"{}\",\
         \"direction\":\"out\",\"bytes\":0,\"process\":\"{}\",\"pid\":{}}}",
        json_escape(lip), json_escape(rip),
        lport, rport, json_escape(&s.proto),
        json_escape(&pname), pid))
}

fn main() {
    let server = env::var("SNITCH_SERVER").unwrap_or_else(|_| "127.0.0.1:8000".into());
    let token = env::var("SNITCH_TOKEN").unwrap_or_default();
    if token.is_empty() {
        eprintln!("snitch-agent: SNITCH_TOKEN is required (collector bearer)");
        process::exit(2);
    }
    let host = env::var("SNITCH_HOST")
        .unwrap_or_else(|_| env::var("HOSTNAME").unwrap_or_else(|_| "agent".into()));
    let interval: u64 = env::var("SNITCH_INTERVAL_SECS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(5).max(1);
    // EN: TLS opt-in — anything but empty/"0" enables it. SNITCH_CA points
    //     at an extra PEM bundle for collectors on a private CA.
    // FR: TLS opt-in — tout sauf vide/« 0 » l'active. SNITCH_CA pointe vers
    //     un bundle PEM additionnel pour les collecteurs en CA privée.
    let use_tls = !matches!(env::var("SNITCH_TLS").as_deref(),
                            Err(_) | Ok("") | Ok("0"));
    let ca_path = env::var("SNITCH_CA").ok().filter(|s| !s.is_empty());

    let mut seen: HashSet<Sock> = HashSet::new();
    let mut pending: Vec<String> = Vec::new();
    eprintln!("snitch-agent {AGENT_ID} → {server} as '{host}' every {interval}s{}",
              if use_tls { " (TLS)" } else { "" });

    loop {
        let now = socket_table();
        // EN: build the inode→pid map ONLY when the diff is non-empty —
        //     the /proc fd walk is O(all fds) and pointless otherwise.
        // FR: ne construire la map inode→pid QUE si le diff n'est pas
        //     vide — le parcours /proc/fd coûte O(tous les fds).
        let new: Vec<&Sock> = now.difference(&seen).collect();
        if !new.is_empty() {
            let pids = inode_pid_map();
            for s in new {
                if let Some(ev) = sock_to_event(s, &pids) {
                    pending.push(ev);
                }
            }
        }
        // EN: forget departed sockets so reconnecting flaps re-report —
        //     the collector's own dedup decides what is noise.
        // FR: oublier les sockets partis pour re-signaler les flaps —
        //     la dédup du collecteur tranche ce qui est du bruit.
        seen = now;
        if !pending.is_empty() {
            let chunk: Vec<String> = pending
                .drain(..pending.len().min(MAX_EVENTS_PER_POST)).collect();
            match post_batch(&server, &token, &host, &chunk,
                             use_tls, ca_path.as_deref()) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("snitch-agent: {e}");
                    // EN: bounded retry — requeue but never grow past the cap.
                    // FR: retry borné — remise en file sans jamais dépasser le cap.
                    pending.splice(0..0, chunk.into_iter());
                    pending.truncate(MAX_EVENTS_PER_POST);
                }
            }
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

// ── unit tests / tests unitaires ────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ip_v4_is_little_endian() {
        // EN: 0100007F stored LE → 127.0.0.1 / FR: LE → 127.0.0.1
        assert_eq!(hex_ip("0100007F", false), "127.0.0.1");
        assert_eq!(hex_ip("0A010203", false), "3.2.1.10");
    }

    #[test]
    fn hex_ip_v6_groups_swapped() {
        // EN: ::1 is "00000000000000000000000001000000" in /proc — the last
        //     u32 group holds 1 in LE. / FR: ::1 vaut « …01000000 » en
        //     /proc — le dernier groupe u32 porte 1 en LE.
        assert_eq!(hex_ip("00000000000000000000000001000000", true), "::1");
        assert_eq!(hex_ip("bad", true), "");
    }

    #[test]
    fn parse_lines_extracts_flows_and_inodes() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                     0: 0100007F:C000 0A010203:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345\n\
                     1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99999\n";
        let mut s = HashSet::new();
        parse_lines(table, "tcp", false, &mut s);
        assert_eq!(s.len(), 1);                       // EN: LISTEN row dropped / FR: ligne LISTEN ignorée
        let sock = s.iter().next().unwrap();
        assert_eq!(sock.inode, 12345);
        assert_eq!(sock.remote, "3.2.1.10:443");      // EN: LE decode / FR: décodage LE
        assert_eq!(sock.local, "127.0.0.1:49152");
    }

    #[test]
    fn event_includes_process_attribution() {
        let mut pids = std::collections::HashMap::new();
        pids.insert(42u64, (1337u32, "evil".to_string()));
        let s = Sock { proto: "tcp".into(), local: "10.0.0.5:5".into(),
                       remote: "8.8.8.8:53".into(), state: 1, inode: 42 };
        let ev = sock_to_event(&s, &pids).unwrap();
        assert!(ev.contains("\"process\":\"evil\"") && ev.contains("\"pid\":1337"));
        assert!(ev.contains("\"dst_ip\":\"8.8.8.8\""));
    }

    #[test]
    fn event_skips_unconnected() {
        let s = Sock { proto: "udp".into(), local: "0.0.0.0:53".into(),
                       remote: "0.0.0.0:0".into(), state: 7, inode: 1 };
        assert!(sock_to_event(&s, &Default::default()).is_none());
    }

    #[test]
    fn json_escapes_quotes_and_control() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\u000ad");
    }
}
