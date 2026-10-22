//! Snitch agent — lightweight remote sensor for a Snitch collector.
//! Agent Snitch — capteur léger pour un collecteur Snitch.
//!
//! EN: Watches the host's live socket table (Linux: /proc/net/{tcp,tcp6,
//!     udp,udp6}; falls back to a periodic scan) and pushes the DIFF —
//!     new outbound/established endpoints only — to the collector's
//!     `POST /ingest/events` endpoint, contract `snitch-agent/1`.
//!
//!     Deliberately zero-dependency and honest about scope:
//!       * it observes SOCKETS, it does not sniff packets — no payloads,
//!         no SNI, no DNS answers (the collector's own pcap path keeps
//!         those duties on the host it runs on);
//!       * pid↔process attribution needs /proc/*/fd walking — marked
//!         TODO below rather than half-done;
//!       * HTTP only for the same reason gossip allows http: LAN/trust
//!         domain; run behind a WireGuard/TLS tunnel on hostile links.
//!
//!     Config: SNITCH_SERVER="collector:8000"  SNITCH_TOKEN="<bearer>"
//!             SNITCH_HOST="agent-name"        SNITCH_INTERVAL_SECS=5
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
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AGENT_ID: &str = "snitch-agent/1";
const MAX_EVENTS_PER_POST: usize = 1000; // EN: matches backend cap / FR: cap backend

#[derive(Clone, PartialEq, Eq, Hash)]
struct Sock {
    proto: String,      // "tcp" | "udp"
    local: String,      // "ip:port"
    remote: String,     // "ip:port" — empty when LISTEN/unconnected
    state: u8,
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

fn parse_table(path: &str, proto: &str, v6: bool, out: &mut HashSet<Sock>) {
    // EN: One line: sl local rem st …  — rem "00000000:0000" = unconnected.
    // FR: Une ligne : sl local rem st … — rem « 00000000:0000 » = non connecté.
    let Ok(text) = fs::read_to_string(path) else { return };
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
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
        out.insert(Sock { proto: proto.into(), local, remote, state });
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
              events: &[String]) -> Result<(), String> {
    // EN: Minimal HTTP/1.1 POST, no TLS stack — see module doc for the
    //     trust-domain reasoning. Bearer auth on every request.
    // FR: POST HTTP/1.1 minimal, pas de TLS — voir le doc module pour le
    //     domaine de confiance. Bearer sur chaque requête.
    let body = format!(
        "{{\"agent\":\"{}\",\"host\":\"{}\",\"events\":[{}]}}",
        json_escape(AGENT_ID), json_escape(host), events.join(","));
    let req = format!(
        "POST /ingest/events HTTP/1.1\r\nHost: {server}\r\n\
         Authorization: Bearer {token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len());
    let mut stream = TcpStream::connect(server)
        .map_err(|e| format!("connect {server}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    match resp.split(' ').nth(1) {
        Some(code) if code.starts_with('2') => Ok(()),
        _ => Err(format!("ingest rejected: {}",
                         resp.lines().next().unwrap_or("?"))),
    }
}

fn sock_to_event(s: &Sock) -> Option<String> {
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
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!(
        "{{\"ts\":{ts},\"src_ip\":\"{}\",\"dst_ip\":\"{}\",\
         \"src_port\":{},\"dst_port\":{},\"proto\":\"{}\",\
         \"direction\":\"out\",\"bytes\":0}}",
        json_escape(lip), json_escape(rip),
        lport, rport, json_escape(&s.proto)))
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

    // TODO(pid-attr): walk /proc/<pid>/fd symlinks to map socket inodes
    //   → process name/pid, then fill the `process`/`pid` event fields.
    //   Kept out on purpose until it is exact, not approximate.
    let mut seen: HashSet<Sock> = HashSet::new();
    let mut pending: Vec<String> = Vec::new();
    eprintln!("snitch-agent {AGENT_ID} → {server} as '{host}' every {interval}s");

    loop {
        let now = socket_table();
        for s in now.difference(&seen) {
            if let Some(ev) = sock_to_event(s) {
                pending.push(ev);
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
            match post_batch(&server, &token, &host, &chunk) {
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
