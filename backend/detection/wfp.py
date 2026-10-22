"""
EN: Windows Filtering Platform — USER-MODE backend (no driver, no kernel
    callout). Snitch talks to `fwpuclnt.dll` through ctypes and installs
    ordinary WFP *filters* at the ALE_AUTH_CONNECT layers — exactly what
    `netsh advfirewall` does under the hood, but with per-application
    precision (ALE_APP_ID), per-rule GUID keys and atomic deletes.
    A true *callout* (packet inspection inside the kernel) still needs a
    signed driver — that stays a research item; static block filters do not.

    Why this beats `netsh`:
      * `program=` accepts a name OR path here — we resolve names to the
        running exe and WFP matches the real ALE_APP_ID (canonicalized
        device path), not a display string,
      * filters are added/deleted individually by key (domain re-resolution
        becomes a true delta instead of delete+recreate),
      * IPv4 AND IPv6 connect layers are covered — netsh rules created
        through the advfirewall surface only ever saw IPv4 destinations.
    Requires an elevated process (same requirement as `netsh`); failures are
    reported as honest applied=False by the caller.

FR: Windows Filtering Platform — backend USER-MODE (sans driver ni callout
    noyau). Snitch dialogue avec `fwpuclnt.dll` via ctypes et installe des
    filtres WFP ordinaires sur les couches ALE_AUTH_CONNECT — exactement ce
    que fait `netsh advfirewall` en dessous, mais avec une précision par
    application (ALE_APP_ID), des clés GUID par règle et des suppressions
    atomiques. Un vrai *callout* (inspection dans le noyau) exige toujours
    un driver signé — reste en recherche ; les filtres statiques, non.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import uuid
from typing import Optional

# ── GUID constants (Windows SDK fwpmk.h — values verified against
#    winsdk-10 + OpenVPN's wfp_block.c) / Constantes GUID ────────────────────
_LAYER_V4 = "c38d57d1-05a7-4c33-904f-7fbceee60e82"   # ALE_AUTH_CONNECT_V4
_LAYER_V6 = "4a72393b-319f-44bc-84c3-ba54dcb3b6b4"   # ALE_AUTH_CONNECT_V6
_COND_REMOTE_IP   = "b235ae9a-1d64-49b8-a44c-5ff3d9095045"
_COND_REMOTE_PORT = "c35a604d-d22b-4e1a-91b4-68f674ee674b"
_COND_ALE_APP_ID  = "d78e1e87-8644-4ea5-9437-d809ecefc971"
_SUBLAYER_UNIVERSAL = "eebecc03-ced4-4380-819a-2734397b2b74"

# ── Scalar constants / Constantes scalaires ──────────────────────────────────
RPC_C_AUTHN_WINNT        = 10
FWPM_SESSION_FLAG_DYNAMIC = 1
FWP_EMPTY                = 0
FWP_UINT8                = 1
FWP_UINT16               = 2
FWP_UINT32               = 3
FWP_UINT64               = 4          # EN: value passed by POINTER / FR: valeur par pointeur
FWP_BYTE_ARRAY16_TYPE    = 11         # EN: FWP_DATA_TYPE — fwpmtypes.h / FR: idem
FWP_BYTE_BLOB_TYPE       = 12
# EN: Compound types start at 0x100 — they are NOT small scalars.
#     (Found by the Windows integration job: 19/20 → FWP_E_INVALID_ENUMERATOR)
# FR: Les types composés commencent à 0x100 — pas de petits scalaires.
FWP_V4_ADDR_MASK         = 256
FWP_V6_ADDR_MASK         = 257
FWP_MATCH_EQUAL          = 0
FWP_ACTION_BLOCK         = 0x00001001  # EN: BLOCK | FLAG_TERMINATING / FR: BLOCK | TERMINATING
FWP_E_FILTER_NOT_FOUND   = 0x80320004
_NAME_PREFIX             = "SnitchRule-"


def _guid(text: str):
    """EN: Parse a {xxxxxxxx-…} GUID into the 16-byte Windows layout
    (first three fields little-endian). / FR: Convertit un GUID texte en
    layout mémoire Windows (trois premiers champs little-endian)."""
    return _GUID.from_buffer_copy(uuid.UUID(text).bytes_le)


def _rule_key(rid: str, tag: str = ""):
    """EN: Deterministic filter GUID per (rule, target) — delete-by-key then
    needs no stored handle and survives restarts.
    FR: GUID de filtre déterministe par (règle, cible) — la suppression par
    clé n'exige pas de handle stocké et survit aux redémarrages."""
    return _GUID.from_buffer_copy(
        uuid.uuid5(uuid.NAMESPACE_URL, f"snitch-wfp:{rid}:{tag}").bytes_le)


# ── ctypes structures — layouts match the SDK on Win64 exactly ──────────────
# EN: ctypes unions/structures replicate fwpmtypes.h; alignment is natural.
# FR: les unions/structures ctypes répliquent fwpmtypes.h ; alignement naturel.

class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_uint8 * 8)]


class _BYTE_BLOB(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]


class _DISPLAY_DATA(ctypes.Structure):
    _fields_ = [("name", ctypes.c_wchar_p), ("description", ctypes.c_wchar_p)]


class _VALUE_UNION(ctypes.Union):
    _fields_ = [("uint8", ctypes.c_uint8), ("uint16", ctypes.c_uint16),
                ("uint32", ctypes.c_uint32), ("uint64p", ctypes.c_void_p),
                ("blobp", ctypes.c_void_p), ("ba16p", ctypes.c_void_p),
                ("v4amp", ctypes.c_void_p), ("v6amp", ctypes.c_void_p),
                ("rangep", ctypes.c_void_p)]


class _VALUE(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("v", _VALUE_UNION)]


class _CONDITION(ctypes.Structure):
    _fields_ = [("fieldKey", _GUID), ("matchType", ctypes.c_uint32),
                ("conditionValue", _VALUE)]


class _ACTION_UNION(ctypes.Union):
    _fields_ = [("filterType", _GUID), ("calloutType", _GUID)]


class _ACTION(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("u", _ACTION_UNION)]


class _CTX_UNION(ctypes.Union):
    _fields_ = [("rawContext", ctypes.c_uint64),
                ("providerContextKey", _GUID)]


class _FILTER(ctypes.Structure):
    _fields_ = [("filterKey", _GUID), ("displayData", _DISPLAY_DATA),
                ("flags", ctypes.c_uint32), ("providerKey", ctypes.c_void_p),
                ("providerData", _BYTE_BLOB), ("layerKey", _GUID),
                ("subLayerKey", _GUID), ("weight", _VALUE),
                ("numFilterConditions", ctypes.c_uint32),
                ("filterCondition", ctypes.c_void_p), ("action", _ACTION),
                ("ctx", _CTX_UNION), ("reserved", ctypes.c_void_p),
                ("filterId", ctypes.c_uint64), ("effectiveWeight", _VALUE)]


class _SESSION(ctypes.Structure):
    _fields_ = [("sessionKey", _GUID), ("displayData", _DISPLAY_DATA),
                ("flags", ctypes.c_uint32),
                ("txnWaitTimeoutInMSec", ctypes.c_uint32),
                ("processId", ctypes.c_uint32), ("sid", ctypes.c_void_p),
                ("username", ctypes.c_wchar_p), ("kernelMode", ctypes.c_int32)]


class _V4_ADDR_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32), ("mask", ctypes.c_uint32)]


class _V6_ADDR_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint8 * 16), ("prefixLength", ctypes.c_uint8)]


class _BYTE_ARRAY16(ctypes.Structure):
    _fields_ = [("byteArray16", ctypes.c_uint8 * 16)]


class WfpBackend:
    """EN: Minimal WFP user-mode client — open engine, add block filters with
    deterministic GUID keys, delete by key, purge stale Snitch filters by
    enumerating names. Everything is best-effort and never raises.
    FR: Client WFP user-mode minimal — ouvre le moteur, ajoute des filtres
    de blocage à clés GUID déterministes, supprime par clé, purge les
    filtres Snitch périmés en énumérant les noms. Au mieux, ne lève jamais."""

    def __init__(self):
        self._dll = None
        self._engine = ctypes.c_void_p()
        # EN: pinned ctypes objects — bounded: app blobs accumulate per
        #     add_block, so cap the list (dropping a pin only risks GC of
        #     blobs WFP already copied during FwpmFilterAdd0).
        # FR: objets ctypes épinglés — bornés : les blobs s'accumulent à
        #     chaque add_block, donc caper la liste (retirer un pin ne
        #     risque que le GC de blobs que WFP a déjà copiés).
        self._keepalive: list = []
        self._keepalive_max = 2048

    # ── lifecycle / cycle de vie ─────────────────────────────────────────────

    @staticmethod
    def available() -> bool:
        return os.name == "nt"

    def open(self) -> tuple[bool, str]:
        """EN: Load fwpuclnt + open a non-dynamic session (filters persist —
        Snitch deletes them explicitly by key). Returns (ok, error).
        FR: Charge fwpuclnt + ouvre une session non dynamique (les filtres
        persistent — Snitch les supprime explicitement par clé)."""
        if self._engine.value:
            return True, ""
        if not self.available():
            return False, "windows only"
        try:
            self._dll = ctypes.WinDLL("fwpuclnt")
        except OSError as e:
            return False, f"fwpuclnt unavailable: {e}"
        sess = _SESSION()
        sess.displayData.name = "Snitch"
        sess.displayData.description = "Snitch outbound filters"
        sess.flags = 0                 # EN: persistent / FR: persistante
        sess.processId = os.getpid()
        engine = ctypes.c_void_p()
        rc = self._dll.FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None,
                                       ctypes.byref(sess), ctypes.byref(engine))
        if rc != 0:
            return False, f"FwpmEngineOpen0=0x{rc:08x} (admin required)"
        self._engine = engine
        self._purge_stale()
        return True, ""

    def close(self) -> None:
        if self._dll and self._engine.value:
            self._dll.FwpmEngineClose0(self._engine)
        self._engine = ctypes.c_void_p()

    # ── filters / filtres ────────────────────────────────────────────────────

    def add_block(self, rid: str, conds: list[dict]) -> tuple[bool, str]:
        """EN: Add one BLOCK filter per (layer, address) combination implied
        by `conds` — a condition dict list like:
            {"app": path}      → ALE_APP_ID on BOTH v4+v6 layers
            {"remote": cidr}   → remote addr (+mask) on the matching layer
            {"port": 443}      → remote port on BOTH layers
        Returns (ok, error). Filter keys are uuid5(rid, serialized conds).
        FR: Ajoute un filtre BLOCK par combinaison (couche, adresse) —
        voir le format ci-dessus. Clés uuid5(rid, conditions sérialisées)."""
        if not self._engine.value:
            return False, "engine not open"
        try:
            plan = self._plan(conds)
        except ValueError as e:
            return False, str(e)
        keep: list = []
        try:
            for layer_s, cfields, tag in plan:
                f = _FILTER()
                f.filterKey = _rule_key(rid, tag)
                f.displayData.name = _NAME_PREFIX + rid
                f.displayData.description = "Snitch outbound block"
                f.layerKey = _guid(layer_s)
                f.subLayerKey = _guid(_SUBLAYER_UNIVERSAL)
                weight = ctypes.c_uint64(0xFFFFFFFFFFFFFFFF)
                f.weight.type = FWP_UINT64
                f.weight.v.uint64p = ctypes.cast(
                    ctypes.pointer(weight), ctypes.c_void_p)
                keep.append(weight)
                arr = (_CONDITION * len(cfields))()
                for i, (key_s, vtype, ptr_or_val, pin) in enumerate(cfields):
                    arr[i].fieldKey = _guid(key_s)
                    arr[i].matchType = FWP_MATCH_EQUAL
                    arr[i].conditionValue.type = vtype
                    self._set_value(arr[i].conditionValue.v, vtype, ptr_or_val)
                    keep.append(pin)
                f.numFilterConditions = len(cfields)
                f.filterCondition = ctypes.cast(arr, ctypes.c_void_p)
                keep.append(arr)
                f.action.type = FWP_ACTION_BLOCK
                rc = self._dll.FwpmFilterAdd0(self._engine, ctypes.byref(f),
                                              None, None)
                if rc != 0:
                    return False, f"FwpmFilterAdd0=0x{rc:08x}"
            return True, ""
        except OSError as e:
            return False, str(e)[:200]

    @staticmethod
    def _set_value(union: _VALUE_UNION, vtype: int, val) -> None:
        """EN: Fill the value union — scalar types inline, compound by pointer.
        FR: Remplit l'union — scalaires inline, composés par pointeur."""
        if vtype == FWP_UINT8:
            union.uint8 = val
        elif vtype == FWP_UINT16:
            union.uint16 = val
        elif vtype == FWP_UINT32:
            union.uint32 = val
        elif vtype == FWP_BYTE_BLOB_TYPE:
            union.blobp = val
        elif vtype == FWP_BYTE_ARRAY16_TYPE:
            union.ba16p = val
        elif vtype == FWP_V4_ADDR_MASK:
            union.v4amp = val
        elif vtype == FWP_V6_ADDR_MASK:
            union.v6amp = val

    def _plan(self, conds: list[dict]) -> list:
        """EN: Translate abstract conds → [(layer_guid, [(key,type,val,pin)],
        tag)] — one filter per address so each key stays unique+deletable.
        FR: Traduit les conditions → [(couche, [(clé,type,valeur,pin)],
        tag)] — un filtre par adresse pour des clés uniques/supprimables."""
        app = next((c["app"] for c in conds if "app" in c), None)
        remotes = [c["remote"] for c in conds if "remote" in c]
        port = next((c["port"] for c in conds if "port" in c), None)
        proto = next((c["proto"] for c in conds if "proto" in c), None)
        plan = []
        if app is not None:
            blob = self._app_blob(app)
            if blob is None:
                raise ValueError(f"FwpmGetAppIdFromFileName failed for {app}")
            fields = [(_COND_ALE_APP_ID, FWP_BYTE_BLOB_TYPE,
                       ctypes.cast(ctypes.byref(blob.contents), ctypes.c_void_p),
                       blob)]
            plan += [(_LAYER_V4, fields, "app4"), (_LAYER_V6, fields, "app6")]
            # EN: app blob freed by caller-side pin until add returns — WFP
            #     copies the blob during FwpmFilterAdd0.
            # FR: blob libéré via le pin côté appelant — WFP le copie
            #     pendant FwpmFilterAdd0.
        for net_s in remotes:
            net = ipaddress.ip_network(net_s, strict=False)
            if net.version == 4:
                # EN: FWP_V4_ADDR_AND_MASK stores both fields in NETWORK
                #     byte order (samples fill .addr via InetPton into an
                #     in_addr). int(ip) is host order → swap.
                # FR: FWP_V4_ADDR_AND_MASK stocke les deux champs en ordre
                #     réseau (les samples remplissent .addr via InetPton
                #     dans un in_addr). int(ip) est host order → swap.
                am = _V4_ADDR_MASK(
                    int.from_bytes(net.network_address.packed, "little"),
                    int.from_bytes(net.netmask.packed, "little"))
                cf = (_COND_REMOTE_IP, FWP_V4_ADDR_MASK,
                      ctypes.cast(ctypes.byref(am), ctypes.c_void_p), am)
                plan.append((_LAYER_V4, [cf], f"ip-{net}"))
            else:
                am = _V6_ADDR_MASK(
                    (ctypes.c_uint8 * 16)(*net.network_address.packed),
                    net.prefixlen)
                cf = (_COND_REMOTE_IP, FWP_V6_ADDR_MASK,
                      ctypes.cast(ctypes.byref(am), ctypes.c_void_p), am)
                plan.append((_LAYER_V6, [cf], f"ip-{net}"))
        if port is not None:
            for layer, tag in ((_LAYER_V4, "port4"), (_LAYER_V6, "port6")):
                fields = [(_COND_REMOTE_PORT, FWP_UINT16, int(port), None)]
                if proto:
                    fields.append(("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7",
                                   FWP_UINT8, int(proto), None))
                plan.append((layer, fields, tag))
        return plan

    def delete(self, rid: str, tags: list[str]) -> None:
        """EN: Delete this rule's filters by their deterministic keys —
        missing keys are fine. / FR: Supprime les filtres par leurs clés
        déterministes — les absents sont ignorés."""
        if not self._engine.value:
            return
        for tag in tags:
            key = _rule_key(rid, tag)
            rc = self._dll.FwpmFilterDeleteByKey0(self._engine,
                                                  ctypes.byref(key))
            # EN: FWP_E_FILTER_NOT_FOUND is expected — ignore it.
            # FR: FWP_E_FILTER_NOT_FOUND est attendu — on l'ignore.
            _ = rc

    @staticmethod
    def tags_for(kind: str, value: str,
                 resolved: Optional[list[str]] = None) -> list[str]:
        """EN: Inverse of _plan's tag generation — which keys might exist
        for a rule (used for deletes + domain refresh deltas).
        FR: Inverse de la génération de tags — quelles clés peuvent exister
        pour une règle (suppressions + deltas de re-résolution)."""
        if kind == "process":
            return ["app4", "app6"]
        if kind == "port":
            return ["port4", "port6"]
        nets = resolved if kind == "domain" else [value]
        return [f"ip-{ipaddress.ip_network(n, strict=False)}" for n in nets]

    def _app_blob(self, path: str):
        """EN: FwpmGetAppIdFromFileName0 → FWP_BYTE_BLOB* (canonicalized
        device path the ALE layer matches). None on failure.
        FR: FwpmGetAppIdFromFileName0 → FWP_BYTE_BLOB* (chemin canonique
        que la couche ALE matche). None en cas d'échec."""
        blob = ctypes.POINTER(_BYTE_BLOB)()
        rc = self._dll.FwpmGetAppIdFromFileName0(path, ctypes.byref(blob))
        if rc != 0 or not blob:
            return None
        if len(self._keepalive) >= self._keepalive_max:
            del self._keepalive[:self._keepalive_max // 4]
        self._keepalive.append(blob)   # EN: keep alive; freed w/ engine / FR: gardé vivant
        return blob

    def _purge_stale(self) -> None:
        """EN: Remove leftover SnitchRule-* filters from previous runs —
        enumerates the engine and deletes by key on name-prefix match.
        FR: Retire les filtres SnitchRule-* restés d'exécutions passées —
        énumère le moteur et supprime par clé sur préfixe de nom."""
        enum_h = ctypes.c_void_p()
        rc = self._dll.FwpmFilterCreateEnumHandle0(
            self._engine, None, ctypes.byref(enum_h))
        if rc != 0:
            return
        try:
            while True:
                arr_p = ctypes.POINTER(ctypes.POINTER(_FILTER))()
                n = ctypes.c_uint32(0)
                rc = self._dll.FwpmFilterEnum0(
                    self._engine, enum_h, 64, ctypes.byref(arr_p),
                    ctypes.byref(n))
                if rc != 0 or n.value == 0:
                    break
                for i in range(n.value):
                    name = arr_p[i].contents.displayData.name or ""
                    if name.startswith(_NAME_PREFIX):
                        key = arr_p[i].contents.filterKey
                        self._dll.FwpmFilterDeleteByKey0(
                            self._engine, ctypes.byref(key))
                self._dll.FwpmFreeMemory0(ctypes.byref(arr_p))
        finally:
            self._dll.FwpmFilterDestroyEnumHandle0(self._engine, enum_h)
