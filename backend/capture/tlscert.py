"""
Snitch — passive TLS certificate inspection / inspection passive des
certificats TLS.

EN: Reads the SERVER's TLS Certificate handshake message straight off the
    wire — no MITM, no decryption, no forged certificates. We only parse
    what the server broadcasts in cleartext during the handshake:
      * TLS 1.2 (and 1.3-without-encryption quirks): the Certificate
        message carries the DER chain in the open. We extract the LEAF:
        issuer CN/O, subject CN/O, self-signed flag (issuer==subject DER),
        dNSName SANs and validity window.
      * TLS 1.3: Certificate is encrypted after ServerHello — honestly
        undecodable; we return None rather than pretend.
    Handshakes span TCP segments, so a bounded per-flow reassembly buffer
    (16 KiB/flow, 256 flows max, 30 s TTL — ~4 MiB worst case) stitches
    records before parsing. Everything is drop-safe: malformed DER or an
    incomplete handshake simply yields None.
    The DER reader is deliberately minimal — enough to walk SEQUENCE /
    SET / OID / [0]/[3] wrappers for the TBS certificate fields we need,
    nothing more. Issuer/subject DNs are compared as raw DER bytes, which
    is the strict RFC notion of self-issuance.

FR: Lit le message TLS Certificate du SERVEUR directement sur le fil —
    pas de MITM, pas de déchiffrement, jamais de certificat forgé. On ne
    parse que ce que le serveur diffuse en clair : en TLS 1.2 le message
    Certificate porte la chaîne DER en clair → extraction du certificat
    feuille (issuer CN/O, subject CN/O, auto-signé si issuer==subject,
    SANs dNSName, fenêtre de validité). TLS 1.3 chiffre ce message —
    indécidable honnêtement → None. Les handshakes s'étalent sur plusieurs
    segments TCP : un tampon de réassemblage borné par flux (16 Kio/flux,
    256 flux, TTL 30 s) reconstitue les enregistrements. Tout est tolérant
    aux erreurs : DER malformé ou handshake incomplet → None. Le lecteur
    DER est volontairement minimal.
"""

from __future__ import annotations

import time
from typing import Optional

# EN: Server ports whose replies are worth reassembling — common TLS
#     services. The ClientHello SNI path stays single-segment elsewhere.
# FR: Ports serveur dont les réponses méritent le réassemblage — services
#     TLS courants. Le chemin SNI ClientHello reste mono-segment ailleurs.
_TLS_PORTS = {443, 853, 465, 587, 636, 993, 995, 989, 990, 8443, 9443}

_MAX_FLOWS   = 256
_MAX_BUF     = 16 * 1024
_TTL_S       = 30.0

# EN: flow-key → [buffer_bytes, last_seen_ts]
# FR: clé de flux → [octets tampon, dernier ts]
_FLOWS: dict[tuple, list] = {}


def feed_tls_stream(src: str, sport: int, dst: str, dport: int,
                    payload: bytes) -> Optional[dict]:
    """EN: Feed one TCP segment of a possible TLS stream; returns the leaf
    certificate dict when a complete Certificate handshake has been
    reassembled and parsed, else None. Call for EVERY segment of the flow —
    the buffer handles ordering loosely (record headers self-synchronize).
    FR: Alimenter un segment TCP d'un flux TLS possible ; renvoie le
    certificat feuille quand un handshake Certificate complet a été
    réassemblé, sinon None."""
    if sport not in _TLS_PORTS or not payload:
        return None
    now = time.monotonic()
    # EN: Evict expired + over-cap entries lazily on access — no sweeper.
    # FR: Expurger les entrées expirées à l'accès — pas de balayeur.
    if len(_FLOWS) >= _MAX_FLOWS:
        stale = [k for k, v in _FLOWS.items() if now - v[1] > _TTL_S]
        for k in stale:
            _FLOWS.pop(k, None)
        if len(_FLOWS) >= _MAX_FLOWS:
            _FLOWS.pop(next(iter(_FLOWS)), None)
    key = (src, sport, dst, dport)
    ent = _FLOWS.get(key)
    if ent is None:
        # EN: Only start buffering at a TLS record header — avoids holding
        #     mid-stream garbage on ports that merely share a number.
        # FR: Ne commencer à tamponner qu'au début d'un enregistrement TLS
        #     — évite de garder du bruit de milieu de flux.
        if payload[:2] != b"\x16\x03":
            return None
        ent = _FLOWS[key] = [bytearray(), now]
    ent[1] = now
    ent[0] += payload
    if len(ent[0]) > _MAX_BUF:
        _FLOWS.pop(key, None)
        return None
    cert = _extract_certificate(bytes(ent[0]))
    if cert is not None:
        _FLOWS.pop(key, None)          # EN: done with this flow / FR: flux terminé
    return cert


def _extract_certificate(buf: bytes) -> Optional[dict]:
    """EN: Walk TLS records; find handshake type 11 (Certificate), parse the
    first DER cert → leaf metadata. Returns None while incomplete.
    FR: Parcourt les enregistrements TLS ; trouve le handshake type 11
    (Certificate), parse le premier certificat DER → métadonnées feuille."""
    off = 0
    hs = bytearray()
    while off + 5 <= len(buf):
        rtype, _ver, rlen = buf[off], buf[off + 1:off + 3], \
            int.from_bytes(buf[off + 3:off + 5], "big")
        if rtype != 22:                        # EN: handshake records only
            off += 5 + max(rlen, 0)            # FR: enregistrements handshake
            continue
        if off + 5 + rlen > len(buf):
            return None                        # EN: record still partial
        hs += buf[off + 5:off + 5 + rlen]
        off += 5 + rlen
    # EN: Walk handshake messages inside the reassembled handshake bytes.
    # FR: Parcourt les messages handshake dans les octets réassemblés.
    hoff = 0
    while hoff + 4 <= len(hs):
        htype = hs[hoff]
        hlen = int.from_bytes(hs[hoff + 1:hoff + 4], "big")
        if hoff + 4 + hlen > len(hs):
            return None                        # EN: message still partial
        if htype == 11:                        # EN: Certificate / FR: Certificate
            body = bytes(hs[hoff + 4:hoff + 4 + hlen])
            return _parse_certificate_msg(body)
        hoff += 4 + hlen
    return None


def _parse_certificate_msg(body: bytes) -> Optional[dict]:
    """EN: TLS Certificate message body = 3-byte total len + list of
    3-byte-len DER certs. Parse the FIRST (leaf).
    FR: Corps du message Certificate = longueur totale 3 octets + liste de
    certificats DER préfixés. On parse le PREMIER (feuille)."""
    if len(body) < 6:
        return None
    first_len = int.from_bytes(body[3:6], "big")
    der = body[6:6 + first_len]
    if len(der) < first_len or first_len < 32:
        return None
    try:
        return _parse_x509_leaf(der)
    except Exception:                            # noqa: BLE001 — malformed DER
        return None


# ── Minimal DER reader / Lecteur DER minimal ─────────────────────────────────

def _tlv(buf: bytes, off: int) -> tuple[int, bytes, int]:
    """EN: Read one DER TLV → (tag, value, next_off). Short+long lengths.
    Raises on truncation. / FR: Lit un TLV DER → (tag, valeur, off suivant)."""
    if off + 2 > len(buf):
        raise ValueError("truncated")
    tag = buf[off]
    ln = buf[off + 1]
    pos = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            raise ValueError("bad length")
        ln = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + ln > len(buf):
        raise ValueError("truncated value")
    return tag, buf[pos:pos + ln], pos + ln


def _name_to_dict(name_der: bytes) -> dict:
    """EN: X.501 Name → {cn, o, c, der} by walking RDNSequence →
    RDN SET → AttributeTypeAndValue SEQ {OID, value}.
    FR: X.501 Name → {cn, o, c, der} via RDNSequence → SET → SEQ {OID,valeur}."""
    out = {"cn": "", "o": "", "c": "", "der": name_der}
    _, seq, _ = _tlv(name_der, 0)
    off = 0
    while off < len(seq):
        _, rdn_set, off = _tlv(seq, off)
        soff = 0
        while soff < len(rdn_set):
            _, atv, soff = _tlv(rdn_set, soff)
            aoff = 0
            _, oid, aoff = _tlv(atv, aoff)
            _, val, _ = _tlv(atv, aoff)
            oid_s = ".".join(str(b) for b in _decode_oid(oid))
            try:
                text = val.decode("utf-8", "replace")
            except Exception:
                text = ""
            if oid_s == "2.5.4.3":
                out["cn"] = text
            elif oid_s == "2.5.4.10":
                out["o"] = text
            elif oid_s == "2.5.4.6":
                out["c"] = text
    return out


def _decode_oid(oid: bytes) -> list[int]:
    """EN: DER OID bytes → arc list. / FR: Octets OID DER → liste d'arcs."""
    if not oid:
        return []
    arcs = [oid[0] // 40, oid[0] % 40]
    val = 0
    for b in oid[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(val)
            val = 0
    return arcs


def _parse_x509_leaf(der: bytes) -> dict:
    """EN: Extract leaf fields from a DER certificate:
        issuer/subject (CN/O/C + raw DER), self_signed (issuer==subject),
        SAN dNSNames, not_before/not_after (UTCTime/GeneralizedTime raw).
    FR: Extrait les champs feuille d'un certificat DER : issuer/subject,
    auto-signé (issuer==subject), SANs dNSName, fenêtre de validité brute."""
    tag, cert, _ = _tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a sequence")
    _, tbs, _ = _tlv(cert, 0)
    off = 0
    tag, _, off = _tlv(tbs, off)                   # EN: [0] version or serial
    if tag == 0xA0:                                # EN: explicit version / FR: version explicite
        _, _, off = _tlv(tbs, off)                 # EN: then serial / FR: puis le serial
    _, _, off = _tlv(tbs, off)                     # EN: signature alg / FR: algo signature
    # EN: issuer Name — capture the RAW TLV slice for DER equality checks.
    # FR: issuer Name — on capture la tranche TLV brute pour l'égalité DER.
    iss_start = off
    _, _, off = _tlv(tbs, off)
    issuer_der = tbs[iss_start:off]
    _, validity, off = _tlv(tbs, off)              # EN: validity / FR: validité
    sub_start = off
    _, _, off = _tlv(tbs, off)
    subject_der = tbs[sub_start:off]
    _, _, off = _tlv(tbs, off)                     # EN: subject PKI / FR: PKI sujet

    issuer = _name_to_dict(issuer_der)
    subject = _name_to_dict(subject_der)

    # EN: validity = SEQ { notBefore, notAfter } — UTCTime/GeneralizedTime.
    # FR: validity = SEQ { notBefore, notAfter } — UTCTime/GeneralizedTime.
    voff = 0
    _, nb, voff = _tlv(validity, voff)
    _, na, _ = _tlv(validity, voff)
    not_before = nb.decode("ascii", "replace")
    not_after = na.decode("ascii", "replace")

    # EN: Optional [3] extensions → find SAN (OID 2.5.29.17) → dNSName list.
    # FR: Extensions [3] optionnelles → SAN (OID 2.5.29.17) → liste dNSName.
    sans: list[str] = []
    while off < len(tbs):
        tag, ext_wrap, off = _tlv(tbs, off)
        if tag != 0xA3:
            continue
        _, exts, _ = _tlv(ext_wrap, 0)
        eoff = 0
        while eoff < len(exts):
            _, ext, eoff = _tlv(exts, eoff)
            xoff = 0
            _, oid, xoff = _tlv(ext, xoff)
            if ".".join(str(b) for b in _decode_oid(oid)) != "2.5.29.17":
                continue
            # EN: maybe a critical BOOLEAN then the OCTET STRING value.
            # FR: éventuel BOOLEAN critical puis l'OCTET STRING valeur.
            tag, val, xoff = _tlv(ext, xoff)
            if tag == 0x01:
                _, val, _ = _tlv(ext, xoff)
            _, san_seq, _ = _tlv(val, 0)
            goff = 0
            while goff < len(san_seq):
                gtag, gval, goff = _tlv(san_seq, goff)
                if gtag == 0x82:                   # EN: dNSName IA5String / FR: dNSName IA5String
                    sans.append(gval.decode("ascii", "replace"))

    return {
        "issuer_cn": issuer["cn"], "issuer_o": issuer["o"],
        "subject_cn": subject["cn"], "subject_o": subject["o"],
        "self_signed": issuer_der == subject_der,
        "sans": sans[:24],
        "not_before": not_before, "not_after": not_after,
    }


def san_mismatch(sni: Optional[str], sans: list[str]) -> bool:
    """EN: True when the ClientHello SNI is not covered by any SAN —
    wildcard-aware (*.example.com covers a.example.com only).
    FR: Vrai si le SNI du ClientHello n'est couvert par aucun SAN —
    sensible aux wildcards."""
    if not sni or not sans:
        return False
    sni = sni.lower().rstrip(".")
    for pat in sans:
        pat = pat.lower().rstrip(".")
        if pat == sni:
            return False
        if pat.startswith("*."):
            suffix = pat[1:]                        # EN: ".example.com"
            if sni.endswith(suffix) and "." not in \
                    sni[:-len(suffix)]:
                return False
    return True


def reset() -> None:
    """EN: Drop all flow buffers (tests / shutdown).
    FR: Vide les tampons de flux (tests / arrêt)."""
    _FLOWS.clear()
