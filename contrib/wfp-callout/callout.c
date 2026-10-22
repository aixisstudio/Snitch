/*
 * Snitch — WFP kernel callout skeleton (research only, NOT shipped).
 *
 * EN: Minimal WFP callout registration for the ALE_AUTH_CONNECT_V4 layer —
 *     the outbound-connect authorization point. The classify callback here
 *     PERMITS everything: deciding what to block is policy, and Snitch
 *     policy lives in user mode (backend/detection/wfp.py drives
 *     fwpuclnt.dll). This file shows the register → classify → unregister
 *     skeleton that Microsoft's network/trans/inspect sample and
 *     JaredWright/WFPStarterKit implement in full.
 *
 *     Build: WDK KMDF/WDM driver project; test-sign for your own machine
 *     (bcdedit /set testsigning on), attestation/EV signing for
 *     distribution. An unsigned driver will not load on retail Windows.
 *
 * FR: Enregistrement minimal d'un callout WFP sur la couche
 *     ALE_AUTH_CONNECT_V4 — le point d'autorisation de connexion sortante.
 *     Le callback classify AUTORISE tout : la politique vit en user-mode.
 *     Compile avec le WDK ; signature de test exigée pour charger.
 */

#include <ntddk.h>

/* EN: WFP headers ship in the WDK under km/ — fwpkclnt for the kernel
 *     callout API, fwpsk for the layer/sublayer GUIDs.
 * FR: Les en-têtes WFP du WDK sous km/ — fwpkclnt pour l'API callout
 *     noyau, fwpsk pour les GUID de couches. */
#include <fwpvi.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <fwpkclnt.h>

/* EN: Callout GUID — a real driver generates its own with uuidgen and
 *     keeps it stable across releases. This is a placeholder.
 * FR: GUID du callout — un vrai pilote génère le sien avec uuidgen et le
 *     garde stable entre versions. Placeholder ici. */
// {5fb216a0-0000-0000-0000-000000000001}
static const GUID SNITCH_CALLOUT_KEY = {
    0x5fb216a0, 0x0000, 0x0000,
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
};

static PDEVICE_OBJECT g_device = NULL;
static UINT32 g_callout_id = 0;   /* EN: runtime id chosen by WFP / FR: id choisi par WFP */

/* EN: classifyFn — called in the kernel datapath for every connection the
 *     registered callout's filters match. MUST be fast and non-blocking;
 *     real decisions are either immediate (permit/block via
 *     classifyOut->actionType) or pended via clone-block-reinject (see the
 *     inspect sample). We permit everything.
 * FR: classifyFn — appelé dans le chemin données noyau pour chaque
 *     connexion matchée. DOIT être rapide et non bloquant ; les vraies
 *     décisions sont immédiates (permit/block) ou différées via
 *     clone-block-reinject (cf. sample inspect). Ici on autorise tout. */
static void NTAPI
SnitchClassify(
    _In_ const FWPS_INCOMING_VALUES *fixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *metaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
    UNREFERENCED_PARAMETER(fixedValues);
    UNREFERENCED_PARAMETER(metaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    /* EN: Honest skeleton — the right to hard-permit must be claimed
     *     before setting actionType.
     * FR: Squelette honnête — le droit d'écrire la décision doit être
     *     revendiqué avant de fixer actionType. */
    if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

/* EN: notifyFn — WFP lifecycle notifications for filters that reference
 *     this callout. / FR: notifyFn — notifications de cycle de vie des
 *     filtres référençant ce callout. */
static NTSTATUS NTAPI
SnitchNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* EN: flowDeleteFn — mandatory even with no per-flow state.
 * FR: flowDeleteFn — obligatoire même sans état par flux. */
static void NTAPI
SnitchFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

static NTSTATUS
SnitchRegisterCallout(_In_ PDEVICE_OBJECT device)
{
    FWPS_CALLOUT callout = {0};

    callout.calloutKey = SNITCH_CALLOUT_KEY;
    callout.flags = 0;
    callout.classifyFn = SnitchClassify;
    callout.notifyFn = SnitchNotify;
    callout.flowDeleteFn = SnitchFlowDelete;

    return FwpsCalloutRegister(device, &callout, &g_callout_id);
}

static void
SnitchUnregisterCallout(void)
{
    /* EN: Removes the callout object AND every filter still referencing
     *     it — safe teardown order matters (callout id vs key form).
     * FR: Retire le callout ET tous les filtres qui le référencent —
     *     l'ordre de démontage compte. */
    FwpsCalloutUnregisterById(g_callout_id);
}

static void NTAPI
SnitchUnload(_In_ PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);
    SnitchUnregisterCallout();
    if (g_device != NULL) {
        IoDeleteDevice(g_device);
        g_device = NULL;
    }
}

NTSTATUS NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT driver,
    _In_ PUNICODE_STRING registryPath)
{
    NTSTATUS status;
    UNICODE_STRING name;

    UNREFERENCED_PARAMETER(registryPath);

    driver->DriverUnload = SnitchUnload;

    RtlInitUnicodeString(&name, L"\\Device\\SnitchCallout");
    status = IoCreateDevice(driver, 0, &name, FILE_DEVICE_UNKNOWN,
                            0, FALSE, &g_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SnitchRegisterCallout(g_device);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device);
        g_device = NULL;
        return status;
    }

    /* EN: Registration alone does nothing — a user-mode FWPM_FILTER on
     *     FWPS_LAYER_ALE_AUTH_CONNECT_V4 must reference this callout's key
     *     (action.calloutKey) before classifyFn ever fires. That part is
     *     the user-mode side backend/detection/wfp.py would grow.
     * FR: L'enregistrement seul ne fait rien — un FWPM_FILTER user-mode
     *     sur FWPS_LAYER_ALE_AUTH_CONNECT_V4 doit référencer la clé de ce
     *     callout pour que classifyFn soit invoqué. C'est la partie
     *     user-mode que backend/detection/wfp.py ferait croître. */
    return STATUS_SUCCESS;
}
