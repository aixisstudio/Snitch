//
//  FilterDataProvider.swift
//  Snitch macOS content-filter skeleton — research only, NOT shipped.
//
//  EN: Minimal NEFilterDataProvider showing where Snitch verdicts would
//      land. Every new flow arrives in handleNewFlow(_:); you map the
//      flow's sourceAppAuditToken to a process, look it up in the rule
//      set pushed by the Snitch backend (over XPC — that transport is
//      the real work, not shown here), and return a verdict.
//
//      Requires: Apple Developer account, the
//      com.apple.developer.networking.networkextension entitlement
//      with "content-filter", a system-extension host app, and user
//      approval in System Settings → Network Filters.
//
//      References: Apple SimpleFirewall (WWDC), elastic/endpoint,
//      NuAppFirewall (GPL-2.0 — reference only).
//
//  FR: NEFilterDataProvider minimal montrant où les verdicts Snitch
//      arriveraient. Chaque nouveau flux passe par handleNewFlow(_:) ;
//      on mappe sourceAppAuditToken vers un processus, on consulte les
//      règles poussées par le backend Snitch (via XPC — non montré), et
//      on renvoie un verdict.
//
//      Requiert : compte Apple Developer, entitlement content-filter,
//      app hôte system-extension, approbation utilisateur.
//

import NetworkExtension

/// EN: Rule snapshot shared with the Snitch backend — in a real build
///     this is fed over XPC and hot-swapped on policy change.
/// FR: Instantané de règles partagé avec le backend — dans un vrai
///     build il arrive par XPC et est remplacé à chaud à chaque
///     changement de politique.
struct SnitchPolicy {
    /// EN: Bundle IDs / signing identifiers allowed outbound. Empty =
    ///     allow-all skeleton behaviour.
    /// FR: Identifiants autorisés en sortie. Vide = comportement
    ///     squelette tout-autoriser.
    var blockedHosts: Set<String> = []
    var lockdown: Bool = false
}

final class FilterDataProvider: NEFilterDataProvider {

    private var policy = SnitchPolicy()

    // EN: Provider lifecycle — bring up your XPC listener and load the
    //     last-known policy here, BEFORE flows start arriving.
    // FR: Cycle de vie — monter l'écouteur XPC et charger la dernière
    //     politique connue ici, AVANT l'arrivée des flux.
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    // EN: THE decision point — called for every new socket flow covered
    //     by the filter's NEFilterSettings. Must stay fast; expensive
    //     attribution work belongs in `.pause()` → async → `.resume()`
    //     (see Apple's flow-pause pattern).
    // FR: LE point de décision — appelé pour chaque nouveau flux couvert
    //     par les NEFilterSettings. Doit rester rapide ; le travail
    //     d'attribution coûteux passe par `.pause()` → async → `.resume()`.
    override func handleNewFlow(_ flow: NEFilterFlow,
                                completionHandler: @escaping (NEFilterNewFlowVerdict) -> Void) {
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let remote = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            completionHandler(.allow())
            return
        }

        // EN: Per-app verdict — sourceAppAuditToken identifies the
        //     originating process (NSRunningApplication / proc_pidinfo
        //     resolves it). Skeleton only demonstrates the hook.
        // FR: Verdict par app — sourceAppAuditToken identifie le
        //     processus d'origine (résolu via NSRunningApplication /
        //     proc_pidinfo). Le squelette ne montre que le point d'ancrage.
        _ = socketFlow.sourceAppAuditToken

        if policy.lockdown {
            completionHandler(.drop())
            return
        }
        if policy.blockedHosts.contains(remote.hostname.lowercased()) {
            completionHandler(.drop())
            return
        }
        completionHandler(.allow())
    }
}
