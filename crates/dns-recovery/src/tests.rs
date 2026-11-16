//! U01 concrete tests (SPEC-DNS-FIX.md §12). All run against fakes/mocks and
//! never touch a real NIC. The guarded VM experiment (item e) is recorded in
//! Q1-EVIDENCE.md, not here.

use crate::backend::*;
use crate::fake::*;
use crate::model::*;

const GUID: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
const BUILD: &str = "26300.9974";
const NOW: &str = "2026-11-13T18:08:29Z";

fn cap() -> Capability {
    Capability { os_build: BUILD.into(), reader_revision: 1, api_version: 3, family_supported: true }
}
fn documented() -> FamilySelectorPolicy {
    FamilySelectorPolicy::DocumentedOnly
}
fn exception() -> FamilySelectorPolicy {
    FamilySelectorPolicy::VersionGatedException
}
fn cv4(api: &FakeSettingsApi, reg: &FakeRegistry, p: &FamilySelectorPolicy) -> Result<Snapshot, CaptureError> {
    capture_family(api, reg, GUID, Family::Ipv4, p, cap(), NOW)
}
fn cv6(api: &FakeSettingsApi, reg: &FakeRegistry, p: &FamilySelectorPolicy) -> Result<Snapshot, CaptureError> {
    capture_family(api, reg, GUID, Family::Ipv6, p, cap(), NOW)
}
fn static_v4(api: &FakeSettingsApi, reg: &FakeRegistry, ns: &str, props: Vec<RawProperty>) {
    reg.set_value(GUID, Family::Ipv4, static_value(GUID, Family::Ipv4, ns));
    api.set_response(GUID, 0, raw_settings(Some(ns), props));
}
fn auto_v4(api: &FakeSettingsApi, reg: &FakeRegistry) {
    reg.set_value(GUID, Family::Ipv4, absent_value(GUID, Family::Ipv4));
    api.set_response(GUID, 0, raw_settings(Some(""), vec![]));
}
fn static_v6(api: &FakeSettingsApi, reg: &FakeRegistry, ns: &str, props: Vec<RawProperty>) {
    reg.set_value(GUID, Family::Ipv6, static_value(GUID, Family::Ipv6, ns));
    // The getter echoes the input selector (Q1-EVIDENCE.md): flags_returned=1.
    let mut raw = raw_settings(Some(ns), props);
    raw.flags_returned = DNS_SETTING_IPV6;
    api.set_response(GUID, DNS_SETTING_IPV6, raw);
}
fn auto_v6(api: &FakeSettingsApi, reg: &FakeRegistry) {
    reg.set_value(GUID, Family::Ipv6, absent_value(GUID, Family::Ipv6));
    let mut raw = raw_settings(Some(""), vec![]);
    raw.flags_returned = DNS_SETTING_IPV6;
    api.set_response(GUID, DNS_SETTING_IPV6, raw);
}
fn snap(family: Family, servers: &[&str], props: Vec<ServerProperty>) -> Snapshot {
    Snapshot {
        schema_version: 1,
        family,
        provenance: if servers.is_empty() { Provenance::Automatic } else { Provenance::Static },
        name_server_raw: None,
        ordered_servers: servers.iter().map(|s| CanonicalServer::parse(s).unwrap()).collect(),
        provenance_evidence: ProvenanceEvidence {
            registry_path: String::new(),
            value_exists: false,
            value_type: None,
            raw_value_base64: None,
            api_flags: 0,
            captured_at_utc: NOW.into(),
        },
        server_properties: props,
        context: DnsContext::default(),
        capability: cap(),
    }
}
/// Snapshot whose ordered servers come from `parse_servers` on a raw
/// NameServer string (separator normalization included), not single tokens.
fn snap_parsed(family: Family, raw: &str) -> Snapshot {
    let mut s = snap(family, &[], vec![]);
    s.provenance = Provenance::Static;
    s.ordered_servers = parse_servers(raw).unwrap();
    s
}
fn prop(index: u32, template: Option<&str>, flags: u64) -> ServerProperty {
    ServerProperty { version: 1, server_index: index, prop_type: 1, doh: DohSettings { template: template.map(String::from), flags } }
}
fn backend(
    api: FakeSettingsApi,
    reg: FakeRegistry,
    probe: FakeProbe,
    policy: FamilySelectorPolicy,
) -> ReaderDnsBackend<FakeSettingsApi, FakeRegistry, FakeProbe> {
    ReaderDnsBackend { api, registry: reg, probe, policy, os_build: BUILD.into(), reader_revision: 1, clock: Box::new(|| NOW.into()) }
}

// ---- (a) canonical fingerprint: order / format / duplicates / scope -------

#[test]
fn fingerprint_order_matters() {
    let a = snap(Family::Ipv4, &["9.9.9.9", "149.112.112.112"], vec![]);
    let b = snap(Family::Ipv4, &["149.112.112.112", "9.9.9.9"], vec![]);
    assert_ne!(a.fingerprint(), b.fingerprint());
    assert!(!a.configured_eq(&b));
}

#[test]
fn fingerprint_equivalent_formatting_equal() {
    let a = snap(Family::Ipv6, &["2001:db8::1"], vec![]);
    let b = snap(Family::Ipv6, &["2001:0db8:0000:0000:0000:0000:0000:0001"], vec![]);
    assert_eq!(a.fingerprint(), b.fingerprint());
    assert!(a.configured_eq(&b));
}

/// §12 U01: equivalent separator formatting yields equal fingerprints. These
/// route the raw NameServer forms through `parse_servers` (comma/space split,
/// empty tokens dropped) — not single-token `CanonicalServer::parse`.
#[test]
fn fingerprint_separator_equivalence_through_parse_servers() {
    let forms = [
        "9.9.9.9,149.112.112.112",
        "9.9.9.9, 149.112.112.112",
        "9.9.9.9 149.112.112.112",
        "9.9.9.9 , 149.112.112.112",
        "9.9.9.9,,149.112.112.112",
        " 9.9.9.9,149.112.112.112 ",
    ];
    let reference = snap_parsed(Family::Ipv4, forms[0]);
    for raw in forms {
        let s = snap_parsed(Family::Ipv4, raw);
        assert_eq!(s.ordered_servers, reference.ordered_servers, "raw {raw:?}");
        assert_eq!(s.fingerprint(), reference.fingerprint(), "raw {raw:?}");
        assert!(s.configured_eq(&reference), "raw {raw:?}");
    }
    // Order still matters through parse_servers.
    let reversed = snap_parsed(Family::Ipv4, "149.112.112.112,9.9.9.9");
    assert_ne!(reversed.fingerprint(), reference.fingerprint());
    assert!(!reversed.configured_eq(&reference));
}

/// The same separator equivalence end-to-end: each form enters the reader's
/// registry+getter parse path (`build_snapshot` -> `parse_servers`) and must
/// capture to the same configured fingerprint.
#[test]
fn fingerprint_separator_equivalence_through_capture() {
    let forms = [
        "9.9.9.9,149.112.112.112",
        "9.9.9.9, 149.112.112.112",
        "9.9.9.9 149.112.112.112",
    ];
    let reference = snap_parsed(Family::Ipv4, forms[0]).fingerprint();
    for raw in forms {
        let api = FakeSettingsApi::new();
        let reg = FakeRegistry::new();
        static_v4(&api, &reg, raw, vec![]);
        let s = cv4(&api, &reg, &documented()).unwrap();
        assert_eq!(
            s.ordered_servers.iter().map(|c| c.canonical()).collect::<Vec<_>>(),
            vec!["9.9.9.9", "149.112.112.112"],
            "raw {raw:?}"
        );
        assert_eq!(s.fingerprint(), reference, "raw {raw:?}");
    }
}

#[test]
fn fingerprint_duplicates_preserved() {
    let a = snap(Family::Ipv4, &["9.9.9.9", "9.9.9.9"], vec![]);
    let b = snap(Family::Ipv4, &["9.9.9.9"], vec![]);
    assert_ne!(a.fingerprint(), b.fingerprint());
    assert_eq!(a.ordered_servers.len(), 2);
}

#[test]
fn fingerprint_scope_preserved() {
    let a = snap(Family::Ipv6, &["fe80::1%6"], vec![]);
    let b = snap(Family::Ipv6, &["fe80::1"], vec![]);
    let c = snap(Family::Ipv6, &["fe80::1%7"], vec![]);
    assert_ne!(a.fingerprint(), b.fingerprint());
    assert_ne!(a.fingerprint(), c.fingerprint());
    assert_eq!(a.ordered_servers[0].canonical(), "fe80::1%6");
}

#[test]
fn fingerprint_distinct_families() {
    let v4 = snap(Family::Ipv4, &["9.9.9.9"], vec![]);
    let v6 = snap(Family::Ipv6, &["2620:fe::fe"], vec![]);
    assert_ne!(v4.fingerprint(), v6.fingerprint());
}

#[test]
fn fingerprint_excludes_context_and_capability() {
    let a = snap(Family::Ipv4, &["9.9.9.9"], vec![prop(0, Some("https://x"), 2)]);
    let mut b = a.clone();
    b.context.domain = Some("example.test".into());
    b.context.interface_flags = 99;
    b.capability.os_build = "19041".into();
    b.provenance_evidence.captured_at_utc = "2030-01-01T00:00:00Z".into();
    assert_eq!(a.fingerprint(), b.fingerprint());
    assert!(a.configured_eq(&b));
}

#[test]
fn absent_property_differs_from_zero_flags_property() {
    let absent = snap(Family::Ipv4, &["9.9.9.9"], vec![]);
    let zero = snap(Family::Ipv4, &["9.9.9.9"], vec![prop(0, None, 0)]);
    assert_ne!(absent.fingerprint(), zero.fingerprint());
    assert_eq!(zero.server_properties[0].doh.flags, 0);
}

// ---- (b) provenance matrix ------------------------------------------------

#[test]
fn automatic_v4_static_v6() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    auto_v4(&api, &reg);
    static_v6(&api, &reg, "2620:fe::fe,2620:fe::9", vec![]);
    assert_eq!(cv4(&api, &reg, &documented()).unwrap().provenance, Provenance::Automatic);
    assert_eq!(cv6(&api, &reg, &exception()).unwrap().provenance, Provenance::Static);
}

#[test]
fn static_v4_automatic_v6() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9,149.112.112.112", vec![]);
    auto_v6(&api, &reg);
    assert_eq!(cv4(&api, &reg, &documented()).unwrap().provenance, Provenance::Static);
    assert_eq!(cv6(&api, &reg, &exception()).unwrap().provenance, Provenance::Automatic);
}

#[test]
fn dhcp_ip_with_static_dns_is_static() {
    // Provenance comes from registry NameServer corroborated by the getter,
    // never from DHCP IP assignment. The fixture supplies the IP-assignment
    // input (DHCP) alongside the static DNS override (§12 U01).
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_ip_assignment(GUID, Family::Ipv4, IpAssignment::Dhcp);
    static_v4(&api, &reg, "9.9.9.9", vec![]);
    let s = cv4(&api, &reg, &documented()).unwrap();
    assert_eq!(reg.ip_assignment(GUID, Family::Ipv4), Some(IpAssignment::Dhcp));
    assert_eq!(s.provenance, Provenance::Static);
    assert_eq!(s.ordered_servers[0].canonical(), "9.9.9.9");
}

#[test]
fn static_ip_with_automatic_dns_is_automatic() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_ip_assignment(GUID, Family::Ipv4, IpAssignment::Static);
    // Present-but-empty REG_SZ (raw "0000") + empty getter => automatic.
    reg.set_value(GUID, Family::Ipv4, empty_value(GUID, Family::Ipv4));
    api.set_response(GUID, 0, raw_settings(Some(""), vec![]));
    let s = cv4(&api, &reg, &documented()).unwrap();
    assert_eq!(reg.ip_assignment(GUID, Family::Ipv4), Some(IpAssignment::Static));
    assert_eq!(s.provenance, Provenance::Automatic);
    assert!(s.ordered_servers.is_empty());
    assert!(s.provenance_evidence.value_exists);
    assert_eq!(s.provenance_evidence.raw_value_base64.as_deref(), Some("AAA="));
}

/// §12 U01: provenance follows the DNS override, not the IP assignment. The
/// full 2x2 matrix — flipping the IP-assignment input while holding the DNS
/// configuration fixed must never change the provenance outcome.
#[test]
fn ip_assignment_never_changes_dns_provenance() {
    for assignment in [IpAssignment::Dhcp, IpAssignment::Static] {
        // Static DNS override => Static under either IP assignment.
        let api = FakeSettingsApi::new();
        let reg = FakeRegistry::new();
        reg.set_ip_assignment(GUID, Family::Ipv4, assignment);
        static_v4(&api, &reg, "9.9.9.9", vec![]);
        assert_eq!(cv4(&api, &reg, &documented()).unwrap().provenance, Provenance::Static, "{assignment:?}");
        // Automatic DNS => Automatic under either IP assignment.
        let api = FakeSettingsApi::new();
        let reg = FakeRegistry::new();
        reg.set_ip_assignment(GUID, Family::Ipv4, assignment);
        auto_v4(&api, &reg);
        assert_eq!(cv4(&api, &reg, &documented()).unwrap().provenance, Provenance::Automatic, "{assignment:?}");
    }
}

/// §12 U01: a lease change alters the adapter's effective DNS addresses while
/// the automatic configured baseline stays unchanged. The effective addresses
/// are a real observation input to the capture model (distinct from the
/// configured baseline); the lease change mutates that observation, and the
/// test requires the baseline fingerprint to be equal while the observation
/// itself differs. If the observation ever leaked into the fingerprint, or
/// failed to change with the lease, this test fails.
#[test]
fn lease_churn_does_not_change_automatic_baseline() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    let eff = FakeEffectiveDns::new();
    reg.set_value(GUID, Family::Ipv4, absent_value(GUID, Family::Ipv4));
    // Automatic baseline: no static override; the effective servers come from
    // the active DHCP lease (observation, not configuration).
    eff.set_effective(GUID, Family::Ipv4, &["10.0.0.1"]);
    let mut a = raw_settings(Some(""), vec![]);
    a.domain = Some("lease-one.test".into());
    a.flags_returned = 0;
    api.set_response(GUID, 0, a);
    let (first, eff1) =
        capture_family_with_effective(&api, &reg, &eff, GUID, Family::Ipv4, &documented(), cap(), NOW).unwrap();
    assert_eq!(first.provenance, Provenance::Automatic);
    assert!(first.ordered_servers.is_empty());

    // Lease change: the DHCP lease now hands out different effective DNS
    // servers (and a different connection-specific domain). The configured
    // baseline is untouched.
    eff.set_effective(GUID, Family::Ipv4, &["10.0.0.2", "10.0.0.3"]);
    let mut b = raw_settings(Some(""), vec![]);
    b.domain = Some("lease-two.test".into());
    b.flags_returned = 0;
    api.set_response(GUID, 0, b);
    let (second, eff2) =
        capture_family_with_effective(&api, &reg, &eff, GUID, Family::Ipv4, &documented(), cap(), NOW).unwrap();

    // Automatic baseline fingerprint unchanged...
    assert_eq!(first.fingerprint(), second.fingerprint());
    assert!(first.configured_eq(&second));
    assert_eq!(second.provenance, Provenance::Automatic);
    // ...while the effective observation itself changed with the lease.
    assert_ne!(eff1, eff2);
    assert_eq!(eff1.servers.iter().map(|c| c.canonical()).collect::<Vec<_>>(), vec!["10.0.0.1"]);
    assert_eq!(eff2.servers.iter().map(|c| c.canonical()).collect::<Vec<_>>(), vec!["10.0.0.2", "10.0.0.3"]);
}

// ---- (c) properties: template / AUTO-null / fallback / flags --------------

#[test]
fn explicit_template_preserved() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(0, Some("https://dns.quad9.net/dns-query"), 2)]);
    let s = cv4(&api, &reg, &documented()).unwrap();
    assert_eq!(s.server_properties[0].doh.template.as_deref(), Some("https://dns.quad9.net/dns-query"));
    assert_eq!(s.server_properties[0].doh.flags, 2);
}

#[test]
fn auto_null_template_distinct_from_empty_string() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(0, None, 1)]);
    let null = cv4(&api, &reg, &documented()).unwrap();
    assert_eq!(null.server_properties[0].doh.template, None);
    static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(0, Some(""), 1)]);
    let empty = cv4(&api, &reg, &documented()).unwrap();
    assert_eq!(empty.server_properties[0].doh.template.as_deref(), Some(""));
    assert_ne!(null.fingerprint(), empty.fingerprint());
}

#[test]
fn fallback_and_all_supported_flags_permitted() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    for flags in [4u64, 6, 23] {
        static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(0, Some("https://x"), flags)]);
        let s = cv4(&api, &reg, &documented()).unwrap();
        assert_eq!(s.server_properties[0].doh.flags, flags);
    }
}

#[test]
fn unsupported_flags_refuse_and_free_once() {
    for flags in [8u64, 32, 24] {
        let api = FakeSettingsApi::new();
        let reg = FakeRegistry::new();
        static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(0, Some("https://x"), flags)]);
        let e = cv4(&api, &reg, &documented()).unwrap_err();
        assert_eq!(e, CaptureError::UnsupportedFlags { flags });
        assert_eq!(api.gets(), 1);
        assert_eq!(api.frees(), 1, "freed exactly once on validation failure");
        assert_eq!(api.live_handles(), 0);
    }
}

#[test]
fn invalid_property_index_refuse_and_free_once() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(1, Some("https://x"), 2)]);
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert_eq!(e, CaptureError::InvalidPropertyIndex { index: 1, servers: 1 });
    assert_eq!(api.frees(), 1);
    assert_eq!(api.live_handles(), 0);
}

#[test]
fn unknown_property_version_or_type_refuse() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    let mut bad_version = doh_prop(0, Some("https://x"), 2);
    bad_version.version = 2;
    static_v4(&api, &reg, "9.9.9.9", vec![bad_version]);
    assert_eq!(cv4(&api, &reg, &documented()).unwrap_err(), CaptureError::UnknownProperty { version: 2, prop_type: 1 });
    let mut bad_type = doh_prop(0, Some("https://x"), 2);
    bad_type.prop_type = 2;
    static_v4(&api, &reg, "9.9.9.9", vec![bad_type]);
    assert_eq!(cv4(&api, &reg, &documented()).unwrap_err(), CaptureError::UnknownProperty { version: 1, prop_type: 2 });
    assert_eq!(api.frees(), 2);
}

// ---- (c) refuse-capture cases ---------------------------------------------

#[test]
fn registry_access_denied_refuses_before_getter() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_error(CaptureError::AccessDenied("denied".into()));
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::AccessDenied(_)));
    assert_eq!(api.gets(), 0);
    assert_eq!(api.frees(), 0);
}

#[test]
fn getter_query_failure_refuses_without_free() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    auto_v4(&api, &reg);
    api.set_get_error(CaptureError::QueryFailure("getter failed".into()));
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::QueryFailure(_)));
    assert_eq!(api.gets(), 1);
    assert_eq!(api.frees(), 0, "never free a failed get");
}

#[test]
fn malformed_registry_type_refuses() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv4, RegistryValue {
        path: registry_path(GUID, Family::Ipv4),
        exists: true,
        value_type: Some(4),
        raw: Some(vec![1, 0, 0, 0]),
        text: None,
    });
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::MalformedRegistryType { value_type: 4, .. }));
    assert_eq!(api.gets(), 0);
}

#[test]
fn contradictory_registry_static_getter_automatic() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv4, static_value(GUID, Family::Ipv4, "9.9.9.9"));
    api.set_response(GUID, 0, raw_settings(Some(""), vec![]));
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::ContradictoryProvenance(_)));
    assert_eq!(api.frees(), 1);
}

#[test]
fn contradictory_registry_automatic_getter_static() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv4, absent_value(GUID, Family::Ipv4));
    api.set_response(GUID, 0, raw_settings(Some("9.9.9.9"), vec![]));
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::ContradictoryProvenance(_)));
    assert_eq!(api.frees(), 1);
}

#[test]
fn contradictory_registry_and_getter_lists() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv4, static_value(GUID, Family::Ipv4, "9.9.9.9"));
    api.set_response(GUID, 0, raw_settings(Some("1.1.1.1"), vec![]));
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::ContradictoryProvenance(_)));
}

#[test]
fn profile_policy_override_refuses() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv4, static_value(GUID, Family::Ipv4, "9.9.9.9"));
    let mut raw = raw_settings(Some("9.9.9.9"), vec![]);
    raw.profile_name_server = Some("1.1.1.1".into());
    api.set_response(GUID, 0, raw);
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::ProfilePolicyOverride(_)));
    assert_eq!(api.frees(), 1);
}

#[test]
fn malformed_address_refuses() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "not-an-ip", vec![]);
    let e = cv4(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::MalformedAddress(_)));
    assert_eq!(api.gets(), 0);
}

// ---- (d) lifecycle: free-exactly-once / deep-copy survival / stability ----

#[test]
fn free_exactly_once_on_success() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(0, Some("https://x"), 2)]);
    let _ = cv4(&api, &reg, &documented()).unwrap();
    assert_eq!(api.gets(), 1);
    assert_eq!(api.deep_copies(), 1);
    assert_eq!(api.frees(), 1);
    assert_eq!(api.live_handles(), 0);
}

#[test]
fn deep_copy_survives_free() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9,149.112.112.112", vec![doh_prop(1, Some("https://dns.quad9.net/dns-query"), 2)]);
    let s = cv4(&api, &reg, &documented()).unwrap();
    assert_eq!(api.live_handles(), 0, "handle freed");
    // Mutating the fake's stored response must not affect the owned snapshot.
    api.set_response(GUID, 0, raw_settings(Some("1.1.1.1"), vec![]));
    assert_eq!(s.ordered_servers.iter().map(|c| c.canonical()).collect::<Vec<_>>(), vec!["9.9.9.9", "149.112.112.112"]);
    assert_eq!(s.server_properties[0].server_index, 1);
    assert_eq!(s.server_properties[0].doh.template.as_deref(), Some("https://dns.quad9.net/dns-query"));
}

#[test]
fn use_after_free_is_detected() {
    let api = FakeSettingsApi::new();
    api.set_response(GUID, 0, raw_settings(Some("9.9.9.9"), vec![]));
    let h = api.get(GUID, 0).unwrap();
    assert!(api.deep_copy(&h).is_ok());
    api.free(h);
    assert!(api.deep_copy(&h).is_err(), "deep copy of a freed handle must fail");
}

#[test]
fn changing_state_retries_three_then_fails_without_writes() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv4, static_value(GUID, Family::Ipv4, "9.9.9.9"));
    api.set_sequence(vec![
        raw_settings(Some("9.9.9.9"), vec![doh_prop(0, Some("https://x"), 2)]),
        raw_settings(Some("9.9.9.9"), vec![doh_prop(0, Some("https://x"), 6)]),
        raw_settings(Some("9.9.9.9"), vec![doh_prop(0, Some("https://x"), 2)]),
    ]);
    let e = capture_stable(&api, &reg, GUID, Family::Ipv4, &documented(), cap(), NOW).unwrap_err();
    assert_eq!(e, CaptureError::CaptureUnstable);
    assert_eq!(api.gets(), 3, "at most three attempts");
    assert_eq!(api.frees(), 3);
    assert_eq!(api.writes(), 0, "capture performs no writes");
}

#[test]
fn stable_capture_succeeds_and_readback_matches() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(0, Some("https://x"), 2)]);
    let s = capture_stable(&api, &reg, GUID, Family::Ipv4, &documented(), cap(), NOW).unwrap();
    assert_eq!(api.gets(), 2, "two consecutive agreeing captures");
    assert_eq!(api.writes(), 0);
    let b = backend(api, reg, FakeProbe::new(), documented());
    // Reuse a fresh fake for the backend readback comparison.
    let api2 = FakeSettingsApi::new();
    let reg2 = FakeRegistry::new();
    static_v4(&api2, &reg2, "9.9.9.9", vec![doh_prop(0, Some("https://x"), 2)]);
    let b2 = backend(api2, reg2, FakeProbe::new(), documented());
    let c = b2.capture(GUID, Family::Ipv4).unwrap();
    let r = b2.readback(GUID, Family::Ipv4).unwrap();
    assert!(c.configured_eq(&r));
    assert_eq!(c.fingerprint(), r.fingerprint());
    assert_eq!(s.fingerprint(), c.fingerprint());
    let _ = b;
}

// ---- Q1 policy gate -------------------------------------------------------

#[test]
fn default_policy_refuses_ipv6_but_allows_ipv4() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![]);
    static_v6(&api, &reg, "2620:fe::fe", vec![]);
    assert_eq!(cv4(&api, &reg, &documented()).unwrap().provenance, Provenance::Static);
    let e = cv6(&api, &reg, &documented()).unwrap_err();
    assert!(matches!(e, CaptureError::RefuseUnsupportedTakeover(_)));
    assert_eq!(api.last_flags(), Some(0), "only the IPv4 getter ran");
}

#[test]
fn exception_uses_ipv6_selector_on_approved_build() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v6(&api, &reg, "2620:fe::fe,2620:fe::9", vec![]);
    let s = cv6(&api, &reg, &exception()).unwrap();
    assert_eq!(s.provenance, Provenance::Static);
    assert_eq!(api.last_flags(), Some(DNS_SETTING_IPV6));
    assert_eq!(s.provenance_evidence.api_flags, DNS_SETTING_IPV6);
}

// ---- U01b: version-gated family-selector exception (Q1 ruling) ------------
// Coordinator ruling: Garen, 2026-11-14, under Cino's flow delegation of
// 2026-11-14 00:46 (reported to the owner 09:00). Evidence base: Q1-EVIDENCE.md.
// The four cases below are the envelope's named (a)-(d) fake-backed tests.

/// (a) A build below 20348 refuses the selector path (no getter runs); the
/// boundary build 20348 is accepted, and the documented IPv4 path stays primary
/// even on a low build.
#[test]
fn selector_refused_below_min_build() {
    for build in ["19041", "20347", "", "not-a-build"] {
        let api = FakeSettingsApi::new();
        let reg = FakeRegistry::new();
        static_v6(&api, &reg, "2620:fe::fe", vec![]);
        let capability = Capability { os_build: build.into(), ..cap() };
        let e = capture_family(&api, &reg, GUID, Family::Ipv6, &exception(), capability, NOW).unwrap_err();
        assert!(matches!(e, CaptureError::RefuseUnsupportedTakeover(_)), "build {build:?}");
        assert_eq!(api.gets(), 0, "selector must not run below the minimum build");
        assert_eq!(api.frees(), 0);
    }
    // At the gate (>= 20348) the selector is allowed.
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v6(&api, &reg, "2620:fe::fe", vec![]);
    let capability = Capability { os_build: "20348".into(), ..cap() };
    let s = capture_family(&api, &reg, GUID, Family::Ipv6, &exception(), capability, NOW).unwrap();
    assert_eq!(s.provenance_evidence.api_flags, DNS_SETTING_IPV6);
    // The documented IPv4 path stays primary even on a below-gate build.
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![]);
    let capability = Capability { os_build: "19041".into(), ..cap() };
    let s = capture_family(&api, &reg, GUID, Family::Ipv4, &exception(), capability, NOW).unwrap();
    assert_eq!(s.provenance_evidence.api_flags, 0);
}

/// (b) A selector returning IPv4-shaped or mixed data (or properties not from
/// the IPv6 settings structure) refuses capture, freeing exactly once.
#[test]
fn selector_inconsistent_data_refuses() {
    // IPv4-shaped nameservers from the IPv6 selector.
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv6, static_value(GUID, Family::Ipv6, "9.9.9.9"));
    let mut raw = raw_settings(Some("9.9.9.9"), vec![]);
    raw.flags_returned = DNS_SETTING_IPV6;
    api.set_response(GUID, DNS_SETTING_IPV6, raw);
    let e = cv6(&api, &reg, &exception()).unwrap_err();
    assert!(matches!(e, CaptureError::FamilyInconsistent(_)));
    assert_eq!(api.frees(), 1, "freed exactly once on family inconsistency");
    assert_eq!(api.live_handles(), 0);

    // Mixed IPv4 + IPv6 list.
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv6, static_value(GUID, Family::Ipv6, "2620:fe::fe,9.9.9.9"));
    let mut raw = raw_settings(Some("2620:fe::fe,9.9.9.9"), vec![]);
    raw.flags_returned = DNS_SETTING_IPV6;
    api.set_response(GUID, DNS_SETTING_IPV6, raw);
    let e = cv6(&api, &reg, &exception()).unwrap_err();
    assert!(matches!(e, CaptureError::FamilyInconsistent(_)));
    assert_eq!(api.frees(), 1);

    // flags_returned does not echo the selector: the returned properties are
    // not the IPv6 settings structure.
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    reg.set_value(GUID, Family::Ipv6, static_value(GUID, Family::Ipv6, "2620:fe::fe"));
    let mut raw = raw_settings(Some("2620:fe::fe"), vec![]);
    raw.flags_returned = 0;
    api.set_response(GUID, DNS_SETTING_IPV6, raw);
    let e = cv6(&api, &reg, &exception()).unwrap_err();
    assert!(matches!(e, CaptureError::FamilyInconsistent(_)));
    assert_eq!(api.frees(), 1);
}

/// (c) A selector call error refuses capture (no free of a failed get), and the
/// two-family capture refuses rather than falling back to an IPv4-only snapshot.
#[test]
fn selector_error_refuses() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v6(&api, &reg, "2620:fe::fe", vec![]);
    api.set_get_error(CaptureError::QueryFailure("selector getter failed".into()));
    let e = cv6(&api, &reg, &exception()).unwrap_err();
    assert!(matches!(e, CaptureError::QueryFailure(_)));
    assert_eq!(api.gets(), 1);
    assert_eq!(api.frees(), 0, "never free a failed get");

    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v6(&api, &reg, "2620:fe::fe", vec![]);
    api.set_get_error(CaptureError::AccessDenied("selector denied".into()));
    let e = cv6(&api, &reg, &exception()).unwrap_err();
    assert!(matches!(e, CaptureError::AccessDenied(_)));
    assert_eq!(api.frees(), 0);

    // No IPv4-only fallback: IPv4 succeeds but the IPv6 selector errors, so the
    // complete two-family capture refuses the whole thing.
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![]);
    static_v6(&api, &reg, "2620:fe::fe", vec![]);
    api.set_get_error_for(DNS_SETTING_IPV6, CaptureError::QueryFailure("selector failed".into()));
    let e = capture_two_families(&api, &reg, GUID, &exception(), cap(), NOW).unwrap_err();
    assert!(matches!(e, CaptureError::QueryFailure(_)));
    assert_eq!(api.writes(), 0);
}

/// (d) Happy path: a complete two-family snapshot assembled from a Flags=0 IPv4
/// result plus a selector IPv6 result, using the exact Q1 experiment values.
#[test]
fn two_family_happy_path() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9,149.112.112.112", vec![doh_prop(1, Some("https://dns.quad9.net/dns-query"), 2)]);
    static_v6(&api, &reg, "2620:fe::fe,2620:fe::9", vec![doh_prop(0, Some("https://dns9.quad9.net/dns-query"), 6), doh_prop(1, None, 1)]);
    let two = capture_two_families(&api, &reg, GUID, &exception(), cap(), NOW).unwrap();

    assert_eq!(two.ipv4.family, Family::Ipv4);
    assert_eq!(two.ipv6.family, Family::Ipv6);
    // IPv4 from the documented Flags=0 path; IPv6 from the approved selector.
    assert_eq!(two.ipv4.provenance_evidence.api_flags, 0);
    assert_eq!(two.ipv6.provenance_evidence.api_flags, DNS_SETTING_IPV6);
    assert_eq!(two.ipv4.provenance, Provenance::Static);
    assert_eq!(two.ipv6.provenance, Provenance::Static);
    assert_eq!(two.ipv4.ordered_servers.iter().map(|c| c.canonical()).collect::<Vec<_>>(), vec!["9.9.9.9", "149.112.112.112"]);
    assert_eq!(two.ipv6.ordered_servers.iter().map(|c| c.canonical()).collect::<Vec<_>>(), vec!["2620:fe::fe", "2620:fe::9"]);
    // Per-family properties preserved, including the null AUTO template.
    assert_eq!(two.ipv4.server_properties.len(), 1);
    assert_eq!(two.ipv4.server_properties[0].server_index, 1);
    assert_eq!(two.ipv6.server_properties.len(), 2);
    assert_eq!(two.ipv6.server_properties[0].doh.flags, 6);
    assert_eq!(two.ipv6.server_properties[1].doh.template, None);
    assert_eq!(two.ipv6.server_properties[1].doh.flags, 1);
    // Complete two-family snapshot: distinct fingerprints, deep-owned.
    assert_ne!(two.ipv4.fingerprint(), two.ipv6.fingerprint());
    // capture_stable: two agreeing gets per family, each freed exactly once.
    assert_eq!(api.gets(), 4);
    assert_eq!(api.frees(), 4);
    assert_eq!(api.live_handles(), 0);
    assert_eq!(api.writes(), 0, "capture performs no writes");
}

#[test]
fn unsupported_family_is_excluded() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![]);
    let probe = FakeProbe::new();
    probe.set(GUID, Family::Ipv4, false);
    let b = backend(api, reg, probe, documented());
    let e = b.capture(GUID, Family::Ipv4).unwrap_err();
    assert_eq!(e, CaptureError::UnsupportedFamily(Family::Ipv4));
}

// ---- backend capability ---------------------------------------------------

#[test]
fn capability_fields() {
    let b = backend(FakeSettingsApi::new(), FakeRegistry::new(), FakeProbe::new(), documented());
    let c = b.capability(GUID, Family::Ipv4).unwrap();
    assert_eq!(c.api_version, 3);
    assert_eq!(c.reader_revision, 1);
    assert_eq!(c.os_build, BUILD);
    assert!(c.family_supported);
}

#[test]
fn snapshot_serializes_u64_as_decimal_strings() {
    let api = FakeSettingsApi::new();
    let reg = FakeRegistry::new();
    static_v4(&api, &reg, "9.9.9.9", vec![doh_prop(0, Some("https://x"), 2)]);
    let s = cv4(&api, &reg, &documented()).unwrap();
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["server_properties"][0]["doh"]["flags"], "2");
    assert_eq!(v["server_properties"][0]["type"], 1);
    assert_eq!(v["provenance_evidence"]["api_flags"], "0");
    assert_eq!(v["context"]["interface_flags"], "0");
}
