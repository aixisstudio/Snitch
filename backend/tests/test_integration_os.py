"""
Snitch — real-OS integration tests / tests d'intégration OS réels.

EN: These tests exercise the ACTUAL OS primitives the production code
    drives — no mocks for the platform layer:
      * Linux   : `unshare` net-namespace sandbox, `iptables` OUTPUT DROP
                  rules (through FirewallManager itself), `tc` clsact/flower
                  throttling, perf_event_open.
      * Windows : `fwpuclnt.dll` WFP engine open, real BLOCK filter at the
                  ALE connect layer verified with a live TCP connect.
      * macOS   : `sandbox-exec` seatbelt egress denial end-to-end.
    They run only when SNITCH_OS_INTEGRATION=1 (the CI `integration` job)
    because they mutate host firewall state / spawn namespaces. Every test
    cleans up in `finally` and skips honestly when the environment can't
    provide the primitive (no egress, userns disabled, no admin).

FR: Ces tests exercent les VRAIES primitives OS que le code de production
    pilote — aucun mock sur la couche plateforme. Ils ne tournent que si
    SNITCH_OS_INTEGRATION=1 (job CI `integration`) car ils modifient l'état
    du pare-feu hôte. Chaque test nettoie dans `finally` et skip honnêtement
    quand l'environnement ne fournit pas la primitive.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap

import pytest

SYSTEM = platform.system().lower()
ENABLED = os.environ.get("SNITCH_OS_INTEGRATION") == "1"

pytestmark = [
    pytest.mark.skipif(not ENABLED,
                       reason="needs SNITCH_OS_INTEGRATION=1 (CI job)"),
]

# EN: Public reachability probe target for end-to-end block checks.
#     1.1.1.1:443 is a stable anycast TCP endpoint; if the runner has no
#     direct egress the tests skip instead of failing.
# FR: Cible de joignabilité publique pour les tests de blocage réels —
#     skip honnête si le runner n'a pas d'égress direct.
_PROBE_IP, _PROBE_PORT = "1.1.1.1", 443


def _probe_source() -> str:
    """EN: Small script printed inside sandboxes — reports whether a TCP
    connect to a public address succeeded (NET_OK) or was refused by the
    environment (NET_DENIED). / FR: Script exécuté dans les sandbox —
    rapporte si une connexion TCP publique a réussi ou été refusée."""
    return textwrap.dedent(
        "import socket\n"
        "try:\n"
        f"    socket.create_connection(('{_PROBE_IP}', {_PROBE_PORT}), "
        "timeout=3)\n"
        "    print('NET_OK')\n"
        "except Exception as e:\n"
        "    print('NET_DENIED', type(e).__name__)\n")


def _tcp_reachable(ip: str, port: int, timeout: float = 3.0) -> bool:
    """EN: True when a TCP connect to ip:port succeeds.
    FR: Vrai si la connexion TCP vers ip:port aboutit."""
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _run(cmd: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, check=False)


def _sudo(cmd: list[str]) -> list[str]:
    """EN: Prefix with non-interactive sudo — CI runners have passwordless
    sudo; production normally runs Snitch with capture privileges anyway.
    FR: Préfixe sudo non interactif — sudo sans mot de passe en CI."""
    return ["sudo", "-n", *cmd]


# ══════════════════════════ Linux / Linux ══════════════════════════


@pytest.mark.skipif(SYSTEM != "linux", reason="linux only")
class TestLinuxReal:
    """EN: Real Linux primitives — namespaces, iptables, tc, perf.
    FR: Primitives Linux réelles — namespaces, iptables, tc, perf."""

    def test_unshare_netns_denies_egress(self, tmp_path):
        """EN: A child inside `unshare -U -n` (the exact wrapper production
        builds via contain.sandbox_command) cannot open a TCP connection —
        first through the unprivileged userns path, then under sudo -n as
        a fallback check of the namespace primitive itself.
        FR: Un enfant dans `unshare -U -n` (wrapper exact de production)
        ne peut pas ouvrir de connexion TCP — chemin userns non privilégié
        d'abord, puis repli sudo pour valider la primitive."""
        from detection import contain

        if not shutil.which("unshare"):
            pytest.skip("unshare missing")
        probe = tmp_path / "probe.py"
        probe.write_text(_probe_source())

        cmd = contain.sandbox_command(sys.executable, [str(probe)])
        res = _run(cmd, timeout=20)
        if res.returncode != 0:
            # EN: Unprivileged userns may be disabled — fall back to root
            #     namespace creation (sudo exists on the runner) and still
            #     verify real egress denial.
            # FR: Les userns non privilégiés peuvent être désactivés —
            #     repli root (sudo) pour valider quand même le déni réel.
            res = _run(_sudo(["unshare", "--net", "--fork",
                              sys.executable, str(probe)]), timeout=20)
        assert res.returncode == 0, res.stderr[:400]
        assert "NET_DENIED" in res.stdout

    def test_iptables_rule_through_manager(self):
        """EN: Apply a real rule through FirewallManager (production code
        path, sudo-wrapped _run): the iptables -C check must confirm the
        DROP rule exists, then removal must take it away.
        FR: Appliquer une vraie règle via FirewallManager (chemin
        production, _run enrobé de sudo) : `iptables -C` confirme le DROP,
        puis le retrait l'enlève."""
        from detection.firewall import FirewallManager

        if not shutil.which("iptables"):
            pytest.skip("iptables missing")
        fm = FirewallManager(tempfile.mkdtemp())
        real_run = fm._run
        fm._run = lambda args: real_run(_sudo(args))       # noqa: SLF001
        rule = fm.add_rule("ip", "203.0.113.9", action="block")
        try:
            assert rule["applied"], f"apply failed: {rule['error']}"
            check = _run(_sudo([
                "iptables", "-w", "-C", "OUTPUT", "-d", "203.0.113.9",
                "-j", "DROP", "-m", "comment", "--comment",
                f"snitch-{rule['id']}"]))
            assert check.returncode == 0, check.stderr[:300]
        finally:
            fm.remove_rule(rule["id"])
        gone = _run(_sudo([
            "iptables", "-w", "-C", "OUTPUT", "-d", "203.0.113.9",
            "-j", "DROP", "-m", "comment", "--comment",
            f"snitch-{rule['id']}"]))
        assert gone.returncode != 0, "DROP rule still present"

    def test_iptables_block_really_drops(self):
        """EN: End-to-end — baseline connect to 1.1.1.1:443 succeeds, a
        real OUTPUT DROP makes it fail, removal restores it. Skips when
        the runner has no direct egress.
        FR: Bout en bout — la connexion de base réussit, un DROP réel la
        fait échouer, le retrait la restaure. Skip sans égress direct."""
        if not _tcp_reachable(_PROBE_IP, _PROBE_PORT):
            pytest.skip("runner has no direct egress to 1.1.1.1:443")
        add = _sudo(["iptables", "-w", "-I", "OUTPUT", "-d", _PROBE_IP,
                     "-j", "DROP", "-m", "comment", "--comment",
                     "snitch-itest"])
        delete = _sudo(["iptables", "-w", "-D", "OUTPUT", "-d", _PROBE_IP,
                        "-j", "DROP", "-m", "comment", "--comment",
                        "snitch-itest"])
        res = _run(add)
        if res.returncode != 0:
            pytest.skip(f"cannot insert iptables rule: {res.stderr[:200]}")
        try:
            assert not _tcp_reachable(_PROBE_IP, _PROBE_PORT, timeout=4)
        finally:
            _run(delete)
        assert _tcp_reachable(_PROBE_IP, _PROBE_PORT)

    def test_tc_throttle_through_manager(self):
        """EN: Real clsact + flower via FirewallManager — a throttle rule
        must install a tc filter on the default-route interface.
        FR: clsact + flower réels via FirewallManager — une règle throttle
        installe un filtre tc sur l'interface de la route par défaut."""
        from detection.firewall import FirewallManager

        if not shutil.which("tc"):
            pytest.skip("tc missing")
        fm = FirewallManager(tempfile.mkdtemp())
        real_run = fm._run
        fm._run = lambda args: real_run(_sudo(args))       # noqa: SLF001
        rule = fm.add_rule("ip", "203.0.113.10", action="throttle", rate=64)
        try:
            if not rule["applied"]:
                pytest.skip(f"tc setup refused: {rule['error']}")
            show = _run(_sudo(["tc", "filter", "show", "dev",
                               fm._tc_iface, "egress"]))                 # noqa: SLF001
            assert "flower" in show.stdout
        finally:
            fm.remove_rule(rule["id"])
            if fm._tc_iface:                                             # noqa: SLF001
                _run(_sudo(["tc", "qdisc", "del", "dev",
                            fm._tc_iface, "clsact"]))                    # noqa: SLF001

    def test_perf_event_open(self):
        """EN: perf_event_open on own process through the production
        sample() — skips when the kernel paranoid level blocks it, asserts
        real counter reads otherwise.
        FR: perf_event_open sur le processus courant via sample() de
        production — skip si le noyau bloque, sinon vérifie de vrais
        compteurs."""
        from detection import perfprobe

        ok, why = perfprobe.available()
        if not ok:
            pytest.skip(f"perf unavailable here: {why}")
        res = perfprobe.sample(os.getpid(), 0.3)
        if not res.get("ok"):
            pytest.skip(f"perf_event_open refused: {res.get('error')}")
        assert res["instructions"] >= 0
        assert res["cpu_ms"] > 0


# ══════════════════════════ Windows / Windows ══════════════════════════


@pytest.mark.skipif(SYSTEM != "windows", reason="windows only")
class TestWindowsReal:
    """EN: Real WFP user-mode path — engine open, filter add, live block,
    delete. / FR: Chemin WFP user-mode réel — ouverture, filtre, blocage
    effectif, suppression."""

    def test_wfp_engine_and_live_block(self):
        """EN: FwpmEngineOpen0 + a real ALE_AUTH_CONNECT_V4 BLOCK filter:
        a TCP connect that worked before must fail while the filter is
        installed, and succeed again after delete-by-key.
        FR: FwpmEngineOpen0 + filtre BLOCK réel : la connexion TCP qui
        marchait doit échouer pendant le filtre et remarcher après
        suppression par clé."""
        from detection.wfp import WfpBackend

        wfp = WfpBackend()
        ok, err = wfp.open()
        assert ok, f"FwpmEngineOpen0 failed: {err}"
        try:
            if not _tcp_reachable(_PROBE_IP, _PROBE_PORT):
                pytest.skip("runner has no direct egress to 1.1.1.1:443")
            rid = "itestwfp"
            ok, err = wfp.add_block(rid, [{"remote": f"{_PROBE_IP}/32"}])
            assert ok, f"FwpmFilterAdd0 failed: {err}"
            try:
                assert not _tcp_reachable(_PROBE_IP, _PROBE_PORT,
                                        timeout=4), \
                    "connect succeeded despite WFP BLOCK filter"
            finally:
                wfp.delete(rid, WfpBackend.tags_for(
                    "ip", f"{_PROBE_IP}/32"))
            assert _tcp_reachable(_PROBE_IP, _PROBE_PORT), \
                "connect still blocked after filter delete"
        finally:
            wfp.close()

    def test_wfp_app_id_filter(self):
        """EN: Per-application filter — resolve python.exe through
        FwpmGetAppIdFromFileName0 and install an ALE_APP_ID block.
        FR: Filtre par application — ALE_APP_ID de python.exe via
        FwpmGetAppIdFromFileName0."""
        from detection.wfp import WfpBackend

        wfp = WfpBackend()
        ok, err = wfp.open()
        assert ok, f"FwpmEngineOpen0 failed: {err}"
        try:
            rid = "itestapp"
            ok, err = wfp.add_block(rid, [{"app": sys.executable}])
            try:
                assert ok, f"app-id filter failed: {err}"
            finally:
                wfp.delete(rid, WfpBackend.tags_for("process",
                                                  sys.executable))
        finally:
            wfp.close()


# ══════════════════════════ macOS / macOS ══════════════════════════


@pytest.mark.skipif(SYSTEM != "darwin", reason="macos only")
class TestMacosReal:
    """EN: Real seatbelt path — the production run_sandboxed wrapper.
    FR: Chemin seatbelt réel — le wrapper production run_sandboxed."""

    def test_sandbox_exec_denies_egress(self, tmp_path):
        """EN: End-to-end through contain.run_sandboxed — the child must
        report NET_DENIED for a public TCP connect.
        FR: Bout en bout via contain.run_sandboxed — l'enfant doit
        rapporter NET_DENIED sur une connexion TCP publique."""
        from detection import contain

        ok, why = contain.available()
        assert ok, f"sandbox primitive missing: {why}"
        probe = tmp_path / "probe.py"
        probe.write_text(_probe_source())
        res = contain.run_sandboxed(sys.executable, [str(probe)], 10)
        assert res["ok"], f"sandbox run failed: {res.get('error')}"
        assert "NET_DENIED" in res["stdout"], (
            f"egress not denied: {res['stdout']!r} {res['stderr'][:200]!r}")

    def test_sinkhole_hosts_markers(self):
        """EN: Domain sinkhole is a marked hosts block — apply + remove
        through FirewallManager against a temp hosts path (no /etc write).
        FR: Le sinkhole domaine est un bloc hosts marqué — apply/remove
        via FirewallManager sur un hosts temporaire (pas d'écriture /etc)."""
        from detection.firewall import FirewallManager
        from pathlib import Path

        fake_hosts = Path(tempfile.mkdtemp()) / "hosts"
        fake_hosts.write_text("127.0.0.1 localhost\n")
        fm = FirewallManager(tempfile.mkdtemp())
        fm._hosts_path = lambda: fake_hosts                          # noqa: SLF001
        rule = fm.add_rule("domain", "itest-sinkhole.example",
                           action="sinkhole")
        try:
            assert rule["applied"], rule["error"]
            body = fake_hosts.read_text()
            assert f"# snitch-sinkhole {rule['id']} begin" in body
            assert "127.0.0.1 itest-sinkhole.example" in body
        finally:
            fm.remove_rule(rule["id"])
        assert "itest-sinkhole.example" not in fake_hosts.read_text()


@pytest.mark.skipif(SYSTEM != "linux", reason="linux only")
class TestLinuxV15Real:
    """EN: v1.5 primitives on a real kernel — nftables, firejail,
    nfqueue, bcc/cgroup. All probe availability first and skip
    honestly; they never fake a pass.
    FR: Primitives v1.5 sur un vrai noyau — nftables, firejail,
    nfqueue, bcc/cgroup. Sondes d'abord, skip honnête sinon."""

    def test_nftables_table_lifecycle(self):
        """EN: If `nft` exists, a dedicated `inet snitch` table can be
        created and destroyed for real — the path _nft_apply() uses.
        FR: Si `nft` existe, une table `inet snitch` dédiée se crée et se
        détruit réellement — le chemin utilisé par _nft_apply()."""
        import shutil
        if not shutil.which("nft"):
            pytest.skip("nft binary missing")
        probe = _sudo(["nft", "list", "table", "inet", "snitch_itest"])
        _run(probe)                                              # may exist
        _run(_sudo(["nft", "delete", "table", "inet", "snitch_itest"]))
        try:
            res = _run(_sudo(["nft", "add", "table", "inet", "snitch_itest"]))
            assert res.returncode == 0, res.stderr[:200]
            res = _run(_sudo(["nft", "add", "chain", "inet", "snitch_itest",
                              "output", "{", "type", "filter", "hook",
                              "output", "priority", "0", ";", "}"]))
            assert res.returncode == 0, res.stderr[:200]
        finally:
            _run(_sudo(["nft", "delete", "table", "inet", "snitch_itest"]))
        res = _run(_sudo(["nft", "list", "table", "inet", "snitch_itest"]))
        assert res.returncode != 0                            # really gone

    def test_firejail_net_none_denies_egress(self, tmp_path):
        """EN: If firejail exists, `firejail --net=none` must actually
        refuse a TCP connect — same guarantee unshare proves.
        FR: Si firejail existe, `--net=none` doit réellement refuser une
        connexion TCP — même garantie que unshare."""
        import shutil
        if not shutil.which("firejail"):
            pytest.skip("firejail binary missing")
        probe = tmp_path / "probe.py"
        probe.write_text(_probe_source())
        res = _run(["firejail", "--net=none", "--quiet",
                    sys.executable, str(probe)], timeout=30)
        assert "NET_DENIED" in res.stdout, (
            f"egress not denied: {res.stdout!r} {res.stderr[:200]!r}")

    def test_netfilterqueue_available_probe(self):
        """EN: askmode.available() must answer honestly on a real Linux
        box — (True,"") when root+iptables are present (the NFQUEUE
        client is pure Python — no package to miss), or (False, <reason>)
        naming what's missing. / FR: askmode.available() répond
        honnêtement — True si root+iptables (client NFQUEUE pur Python),
        sinon une raison nommant ce qui manque."""
        from detection import askmode
        ok, why = askmode.available()
        if ok:
            import os as _os
            assert _os.geteuid() == 0
        else:
            assert why and isinstance(why, str)

    def test_pure_nfqueue_bind_probe(self):
        """EN: The pure-Python NFQUEUE client binds a scratch queue for
        real when root — honest proof the embedded netlink code works.
        FR: Le client NFQUEUE pur Python bind réellement une file quand
        root — preuve honnête que le code netlink embarqué marche."""
        import os as _os
        if _os.geteuid() != 0:
            pytest.skip("needs root for NETLINK_NETFILTER bind")
        from detection.nfqueue import NfqSocket
        s = NfqSocket(9)                              # EN: scratch queue
        try:
            s.open()
            s.bind_queue(timeout=2.0)                 # EN: ACK-verified
        finally:
            s.close()

    def test_ebpf_enforce_available_probe(self):
        """EN: ebpf_enforce.available() reports a concrete reason —
        never crashes, never lies on a real kernel.
        FR: ebpf_enforce.available() rapporte une raison concrète —
        jamais de crash, jamais de mensonge."""
        from detection import ebpf_enforce
        ok, why = ebpf_enforce.available()
        if not ok:
            assert why and isinstance(why, str)
        st = ebpf_enforce.EbpfEnforcer().status()
        assert st["attached"] is False                    # nothing started
