//! U08 — legacy pre-journal leftover detection (SPEC-DNS-FIX.md §9, §12 U08).
//!
//! Already-lost pre-Yeager static DNS/DoH settings are **unrecoverable**
//! from present configuration: a legacy repair can never truthfully claim
//! exact original restoration.
//!
//! **Q3 is ruled** (owner decision, recorded in `ENVELOPE-U08.md`):
//! legacy-orphan repair happens ONLY behind explicit elevated approval
//! carrying the warning that the original statics are unrecoverable. Until
//! that approval exists in the flow, detection and reporting only — **no
//! mutation**. This module enforces that: [`request_repair`] refuses without
//! a complete [`ElevatedApproval`], and the approved path only ever clears
//! to automatic (best effort), resumes the automatic target after a crash
//! (never a dead-loopback baseline), and never describes its result as an
//! original restoration.
//!
//! Section 12 law: pure-input classification, no OS calls. OS evidence
//! (adapter snapshots, listener tables, process identity) is gathered by the
//! caller and passed in as [`LegacyInput`]; tests script the full matrix.
//!
//! NOTE: the approval/repair items are exercised only by `cargo test` by
//! §12 design — the GUI process only ever detects and reports (Q3, ruled).
//! The scoped allow keeps non-test builds diagnostics-free.
#![cfg_attr(not(test), allow(dead_code))]

use common::DohProvider;

/// DoH server property for one server-list index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohProp {
    pub version: u32,
    pub index: u32,
    pub prop_type: u32,
    /// Explicit template (`None` = null template / AUTO).
    pub template: Option<String>,
    /// Full flags word. Required-ENABLE with no plaintext fallback is the
    /// only acceptable value on a Yeager public index.
    pub flags: u64,
}

/// One address family's configured state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyConfig {
    /// Ordered canonical IPs (scope preserved where applicable).
    pub servers: Vec<String>,
    pub properties: Vec<DohProp>,
}

/// One adapter's configured DNS state (both families optional: an
/// explicitly unsupported family is simply absent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterSnapshot {
    pub guid: String,
    pub name_hint: String,
    pub v4: Option<FamilyConfig>,
    pub v6: Option<FamilyConfig>,
}

/// What the loopback-listener / process tables say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerEvidence {
    /// A live Yeager GUI process was positively identified (any session).
    pub yeager_gui_live: bool,
    /// Whether UDP/TCP port 53 on loopback is held (None = unknown).
    pub loopback53_listening: Option<bool>,
    /// An unidentified/other DNS listener holds the path.
    pub other_dns_listener: bool,
}

/// Everything classification needs, gathered at the OS seams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyInput {
    pub adapters: Vec<AdapterSnapshot>,
    pub listeners: ListenerEvidence,
}

/// Classification of one adapter (both families judged together; a single
/// unmatched family is never cleared on pair evidence alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyClass {
    /// Conservative exact match on at least one family; the listed families
    /// (non-empty) are the only ones an approved repair may touch. The
    /// `provider` names the matched Yeager provider.
    ExactCandidate {
        provider: DohProvider,
        families: Vec<String>,
    },
    /// Loopback-only (or provider-only Windows-DoH): ambiguous, needs a
    /// manual decision — never automatic repair.
    AmbiguousLoopbackOnly,
    /// Static public resolvers with no Yeager loopback and no exact Yeager
    /// shape: an unrelated public resolver. Never touched.
    PublicOnly,
    /// Yeager-shaped but with an altered property (wrong flags/template,
    /// unexpected entry or order): not an exact candidate, no repair.
    AlteredProperty { detail: String },
    /// A live Yeager GUI was identified: another launch may own the path.
    /// Blocked — detection only.
    BlockedLiveOwner,
    /// Another/unidentified DNS listener holds the path. Blocked.
    BlockedOtherListener,
    /// Ordinary configured DNS with no Yeager shape at all. Never touched.
    NotLegacy,
}

/// Per-adapter verdict with a human-readable reason for the diagnostics UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterVerdict {
    pub guid: String,
    pub class: LegacyClass,
    pub detail: String,
}

/// Full detection report: one verdict per adapter. Detection only — this
/// report authorizes no mutation by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyReport {
    pub verdicts: Vec<AdapterVerdict>,
}

/// The spec's "no plaintext fallback" bit: plaintext fallback allowed on a
/// public index disqualifies the candidate. The exact bit layout lives in
/// the Windows backend; here only the two ruled shapes matter:
/// required-ENABLE with no fallback vs anything else.
pub const FLAG_ENABLE_REQUIRED: u64 = 0x0001;
pub const FLAG_FALLBACK_TO_UDP: u64 = 0x0002;

/// DoH property type for per-server DoH settings (matches the backend's
/// `DnsServerDohProperty` discriminant used in U01–U05 evidence).
pub const PROP_TYPE_DOH: u32 = 1;
pub const PROP_VERSION_1: u32 = 1;

/// First loopback + first provider fallback per family, in order.
fn expected_servers(provider: DohProvider, ipv6: bool) -> [&'static str; 2] {
    let s = provider.servers();
    if ipv6 {
        // v4 loopback first is the spec's canonical shape; the v6 family
        // carries the v6 loopback followed by the first v6 fallback.
        ["::1", s[2]]
    } else {
        ["127.0.0.1", s[0]]
    }
}

/// Classify the whole input. Blockers (live GUI / other listener) are
/// checked first: they veto every adapter, because a live owner or a
/// foreign listener means the path is not ours to judge.
pub fn detect(input: &LegacyInput) -> LegacyReport {
    if input.listeners.yeager_gui_live {
        return LegacyReport {
            verdicts: input
                .adapters
                .iter()
                .map(|a| AdapterVerdict {
                    guid: a.guid.clone(),
                    class: LegacyClass::BlockedLiveOwner,
                    detail: "a live Yeager GUI was identified; the path may be owned — detection only".into(),
                })
                .collect(),
        };
    }
    if input.listeners.other_dns_listener {
        return LegacyReport {
            verdicts: input
                .adapters
                .iter()
                .map(|a| AdapterVerdict {
                    guid: a.guid.clone(),
                    class: LegacyClass::BlockedOtherListener,
                    detail: "another DNS listener holds the path — detection only".into(),
                })
                .collect(),
        };
    }
    LegacyReport {
        verdicts: input.adapters.iter().map(classify_adapter).collect(),
    }
}

fn classify_adapter(a: &AdapterSnapshot) -> AdapterVerdict {
    let mut exact_families: Vec<(DohProvider, &str)> = Vec::new();
    let mut altered: Vec<String> = Vec::new();
    let mut loopback_only = false;
    let mut public_only = false;
    let mut not_legacy = true;

    for (family, name) in [(&a.v4, "ipv4"), (&a.v6, "ipv6")] {
        let Some(cfg) = family else { continue };
        match classify_family(cfg, name == "ipv6") {
            FamilyVerdict::Exact(p) => {
                not_legacy = false;
                exact_families.push((p, name));
            }
            FamilyVerdict::Altered(d) => {
                not_legacy = false;
                altered.push(format!("{name}: {d}"));
            }
            FamilyVerdict::LoopbackOnly => {
                not_legacy = false;
                loopback_only = true;
            }
            FamilyVerdict::PublicOnly => {
                not_legacy = false;
                public_only = true;
            }
            FamilyVerdict::Other => {}
        }
    }

    // Pair-family evidence improves confidence but never authorizes clearing
    // an unmatched family: only exactly-matched families are listed.
    if !exact_families.is_empty() && altered.is_empty() {
        let provider = exact_families[0].0;
        // All exact families must agree on one provider; a split across
        // providers is not an exact candidate for either.
        if exact_families.iter().all(|(p, _)| *p == provider) {
            let families = exact_families.iter().map(|(_, f)| f.to_string()).collect();
            return AdapterVerdict {
                guid: a.guid.clone(),
                class: LegacyClass::ExactCandidate { provider, families },
                detail: format!(
                    "exact legacy {} shape (loopback + first fallback, explicit template, required DoH, no fallback)",
                    provider.label()
                ),
            };
        }
        return AdapterVerdict {
            guid: a.guid.clone(),
            class: LegacyClass::AlteredProperty {
                detail: "exact-shaped families disagree on provider".into(),
            },
            detail: "exact-shaped families disagree on provider".into(),
        };
    }
    if !altered.is_empty() {
        return AdapterVerdict {
            guid: a.guid.clone(),
            class: LegacyClass::AlteredProperty {
                detail: altered.join("; "),
            },
            detail: altered.join("; "),
        };
    }
    if loopback_only && !public_only {
        return AdapterVerdict {
            guid: a.guid.clone(),
            class: LegacyClass::AmbiguousLoopbackOnly,
            detail: "loopback-only without the provider fallback: ambiguous, needs a manual decision".into(),
        };
    }
    if public_only {
        return AdapterVerdict {
            guid: a.guid.clone(),
            class: LegacyClass::PublicOnly,
            detail: "public resolvers without any Yeager loopback: an unrelated configuration — never touched".into(),
        };
    }
    if not_legacy {
        return AdapterVerdict {
            guid: a.guid.clone(),
            class: LegacyClass::NotLegacy,
            detail: "ordinary configured DNS with no Yeager shape — never touched".into(),
        };
    }
    AdapterVerdict {
        guid: a.guid.clone(),
        class: LegacyClass::AmbiguousLoopbackOnly,
        detail: "ambiguous Yeager-adjacent shape: manual decision required".into(),
    }
}

enum FamilyVerdict {
    Exact(DohProvider),
    Altered(String),
    LoopbackOnly,
    PublicOnly,
    Other,
}

fn classify_family(cfg: &FamilyConfig, ipv6: bool) -> FamilyVerdict {
    let loopback = if ipv6 { "::1" } else { "127.0.0.1" };
    if cfg.servers.is_empty() {
        return FamilyVerdict::Other;
    }
    if cfg.properties.is_empty() {
        // No property evidence (e.g. effective-list-only gathering, which
        // cannot see DoH templates/flags): never claim exact candidacy.
        // Loopback-first is ambiguous and needs a manual decision; static
        // public lists without Yeager loopback are unrelated.
        if cfg.servers.first().is_some_and(|s| s == loopback) {
            return FamilyVerdict::LoopbackOnly;
        }
        return FamilyVerdict::PublicOnly;
    }
    let is_loopback = |s: &String| s.as_str() == loopback;
    if cfg.servers.iter().all(is_loopback) {
        return FamilyVerdict::LoopbackOnly;
    }
    // Try each provider's exact shape.
    for provider in DohProvider::ALL {
        let expected = expected_servers(provider, ipv6);
        if cfg.servers.len() == expected.len()
            && cfg.servers.iter().zip(expected).all(|(a, b)| *a == b)
        {
            return match check_properties(cfg, provider, &expected) {
                Ok(()) => FamilyVerdict::Exact(provider),
                Err(d) => FamilyVerdict::Altered(d),
            };
        }
    }
    // Static but Yeager-adjacent: loopback present yet not the exact
    // shape (out of place, wrong order, extra entries), or the exact set
    // in the wrong order. Never an exact candidate.
    if cfg.servers.iter().any(|s| s == loopback) {
        return FamilyVerdict::Altered("loopback present but not the exact provider shape".into());
    }
    // Any static public list without Yeager loopback: unrelated until proven
    // otherwise — and nothing here can prove otherwise.
    FamilyVerdict::PublicOnly
}

fn check_properties(cfg: &FamilyConfig, provider: DohProvider, expected: &[&str]) -> Result<(), String> {
    for (i, server) in expected.iter().enumerate() {
        let is_loopback = *server == "127.0.0.1" || *server == "::1";
        let prop = cfg.properties.iter().find(|p| p.index as usize == i);
        if is_loopback {
            // The loopback index carries no DoH property.
            if prop.is_some() {
                return Err(format!("unexpected DoH property on loopback index {i}"));
            }
            continue;
        }
        let Some(p) = prop else {
            return Err(format!("missing DoH property on public index {i}"));
        };
        if p.version != PROP_VERSION_1 || p.prop_type != PROP_TYPE_DOH {
            return Err(format!("unknown property version/type on index {i}"));
        }
        if p.template.as_deref() != Some(provider.template()) {
            return Err(format!("property template on index {i} is not the explicit {} template", provider.label()));
        }
        if p.flags & FLAG_ENABLE_REQUIRED == 0 {
            return Err(format!("DoH not required on public index {i}"));
        }
        if p.flags & FLAG_FALLBACK_TO_UDP != 0 {
            return Err(format!("plaintext fallback allowed on public index {i}"));
        }
    }
    if cfg.properties.len() > expected.len() {
        return Err("unexpected extra DoH properties".into());
    }
    Ok(())
}

/// Explicit elevated approval for a legacy repair (Q3, ruled). All three
/// conditions must hold; the warning text is part of the approval — the
/// operator must have seen that the original statics are unrecoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevatedApproval {
    /// The repair runs in an elevated context (service/approved helper).
    pub elevated: bool,
    /// The operator was warned — and acknowledged — that the original
    /// static settings are unrecoverable and cannot be restored.
    pub warned_statics_lost: bool,
    /// Human-readable identity of the approver, for the audit trail.
    pub approver: String,
}

/// Outcome of [`request_repair`]. The default (no approval) is refusal:
/// detection and reporting only, no mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairDecision {
    /// No repair: missing approval, not elevated, warning not shown, or no
    /// exact candidate. Nothing was — or will be — mutated.
    Refused { reason: String },
    /// Approved: clear exactly the listed families to automatic (DHCP /
    /// router DNS), with the unrecoverable-statics warning attached. This
    /// is a best-effort automatic repair, never an original restoration.
    ApprovedClear {
        guid: String,
        families: Vec<String>,
        warning: String,
    },
}

/// The mandatory warning: original statics are lost and cannot be rebuilt.
pub fn statics_lost_warning() -> String {
    "Yeager cannot recover the static DNS settings from before Yeager: they were not recorded and cannot be reconstructed. Clearing now only restores automatic (DHCP/router) DNS as a best effort — it never restores the original configuration.".into()
}

/// Decide a legacy repair for one adapter verdict. Only
/// [`LegacyClass::ExactCandidate`] families with a complete approval are
/// ever cleared; everything else is refused with a reason.
pub fn request_repair(verdict: &AdapterVerdict, approval: Option<&ElevatedApproval>) -> RepairDecision {
    let families = match &verdict.class {
        LegacyClass::ExactCandidate { families, .. } => families.clone(),
        other => {
            return RepairDecision::Refused {
                reason: format!("not an exact legacy candidate ({other:?}); repair refused"),
            };
        }
    };
    let Some(approval) = approval else {
        return RepairDecision::Refused {
            reason: "legacy repair requires explicit elevated approval; detection only".into(),
        };
    };
    if !approval.elevated {
        return RepairDecision::Refused {
            reason: "legacy repair requires an elevated context; repair refused".into(),
        };
    }
    if !approval.warned_statics_lost {
        return RepairDecision::Refused {
            reason: "the operator must acknowledge that the original statics are unrecoverable; repair refused".into(),
        };
    }
    if approval.approver.trim().is_empty() {
        return RepairDecision::Refused {
            reason: "approval carries no approver identity; repair refused".into(),
        };
    }
    RepairDecision::ApprovedClear {
        guid: verdict.guid.clone(),
        families,
        warning: statics_lost_warning(),
    }
}

/// The replay target after a crash during an approved repair: automatic
/// (DHCP/router) DNS — never the dead-loopback baseline, and never
/// described as an original restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairTarget {
    Automatic,
}

pub fn resume_target_after_crash() -> RepairTarget {
    RepairTarget::Automatic
}

/// Durable approved-repair intent (spec §9): the GUI records the exact
/// candidate it approved (behind Q3 elevated approval) before clearing, so
/// a crash replays the automatic target instead of the dead loopback.
/// Stored as tiny JSON next to the journal dir; replay returns the recorded
/// families when present.
pub fn intent_file(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("legacy-repair-intent.json")
}

/// Record an approved repair intent. Overwrites any previous intent for the
/// same adapter. IO errors are returned as strings for the diagnostics UI.
pub fn record_repair_intent(
    dir: &std::path::Path,
    guid: &str,
    families: &[String],
) -> Result<(), String> {
    let payload = serde_json::json!({
        "guid": guid,
        "families": families,
        "target": "automatic",
        "recorded_at_utc": chrono_stamp(),
    });
    let text = serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(intent_file(dir), text).map_err(|e| e.to_string())
}

/// Replay a recorded intent after a crash: returns the recorded adapter +
/// families plus the automatic target. `None` when no intent was recorded.
/// A crash never resumes the dead loopback — only this recorded automatic
/// target.
pub fn replay_repair_intent(dir: &std::path::Path) -> Option<(String, Vec<String>, RepairTarget)> {
    let text = std::fs::read_to_string(intent_file(dir)).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    if v.get("target").and_then(|t| t.as_str()) != Some("automatic") {
        return None;
    }
    let guid = v.get("guid").and_then(|g| g.as_str())?.to_string();
    let families = v
        .get("families")
        .and_then(|f| f.as_array())?
        .iter()
        .filter_map(|s| s.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();
    if guid.is_empty() || families.is_empty() {
        return None;
    }
    Some((guid, families, RepairTarget::Automatic))
}

fn chrono_stamp() -> String {
    // No chrono dependency in this crate: seconds since epoch is enough to
    // order intents for diagnostics.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

/// Truthful description of an approved repair result. The word "original"
/// never appears here: nothing original was — or could be — restored.
pub fn describe_repair(guid: &str, families: &[String]) -> String {
    format!(
        "Best-effort automatic repair on {guid} ({}): cleared to automatic DNS. The pre-Yeager static settings were not recorded and were not restored.",
        families.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doh_prop(index: u32, template: &str) -> DohProp {
        DohProp {
            version: PROP_VERSION_1,
            index,
            prop_type: PROP_TYPE_DOH,
            template: Some(template.into()),
            flags: FLAG_ENABLE_REQUIRED,
        }
    }

    fn exact_family(provider: DohProvider, ipv6: bool) -> FamilyConfig {
        let expected = expected_servers(provider, ipv6);
        let properties = expected
            .iter()
            .enumerate()
            .filter(|(_, s)| **s != "127.0.0.1" && **s != "::1")
            .map(|(i, _)| doh_prop(i as u32, provider.template()))
            .collect();
        FamilyConfig {
            servers: expected.iter().map(|s| s.to_string()).collect(),
            properties,
        }
    }

    fn quiet_input() -> LegacyInput {
        LegacyInput {
            adapters: Vec::new(),
            listeners: ListenerEvidence {
                yeager_gui_live: false,
                loopback53_listening: Some(false),
                other_dns_listener: false,
            },
        }
    }

    fn adapter(guid: &str, v4: Option<FamilyConfig>, v6: Option<FamilyConfig>) -> AdapterSnapshot {
        AdapterSnapshot {
            guid: guid.into(),
            name_hint: "Ethernet".into(),
            v4,
            v6,
        }
    }

    // ---- detection matrix (§9) -----------------------------------------

    #[test]
    fn exact_candidate_both_families() {
        let mut input = quiet_input();
        input.adapters.push(adapter(
            "g1",
            Some(exact_family(DohProvider::Cloudflare, false)),
            Some(exact_family(DohProvider::Cloudflare, true)),
        ));
        let report = detect(&input);
        assert_eq!(report.verdicts.len(), 1);
        assert_eq!(
            report.verdicts[0].class,
            LegacyClass::ExactCandidate {
                provider: DohProvider::Cloudflare,
                families: vec!["ipv4".into(), "ipv6".into()],
            }
        );
    }

    #[test]
    fn exact_candidate_single_family_does_not_authorize_other() {
        // Pair-family evidence improves confidence but never authorizes
        // clearing an unmatched family: only the exact family is listed.
        let mut input = quiet_input();
        input.adapters.push(adapter(
            "g1",
            Some(exact_family(DohProvider::Google, false)),
            None,
        ));
        let report = detect(&input);
        assert_eq!(
            report.verdicts[0].class,
            LegacyClass::ExactCandidate {
                provider: DohProvider::Google,
                families: vec!["ipv4".into()],
            }
        );
    }

    #[test]
    fn loopback_only_is_ambiguous_never_repair() {
        let mut input = quiet_input();
        input.adapters.push(adapter(
            "g1",
            Some(FamilyConfig {
                servers: vec!["127.0.0.1".into()],
                properties: Vec::new(),
            }),
            None,
        ));
        let report = detect(&input);
        assert_eq!(report.verdicts[0].class, LegacyClass::AmbiguousLoopbackOnly);
        // And the approval path refuses it: not exact.
        assert!(matches!(
            request_repair(&report.verdicts[0], Some(&approval())),
            RepairDecision::Refused { .. }
        ));
    }

    #[test]
    fn public_only_is_never_touched() {
        let mut input = quiet_input();
        input.adapters.push(adapter(
            "g1",
            Some(FamilyConfig {
                servers: vec!["8.8.8.8".into(), "8.8.4.4".into()],
                properties: Vec::new(),
            }),
            None,
        ));
        let report = detect(&input);
        assert_eq!(report.verdicts[0].class, LegacyClass::PublicOnly);
        assert!(matches!(
            request_repair(&report.verdicts[0], Some(&approval())),
            RepairDecision::Refused { .. }
        ));
    }

    #[test]
    fn altered_property_variants_rejected() {
        // Plaintext fallback allowed on the public index.
        let mut fallback = exact_family(DohProvider::Cloudflare, false);
        fallback.properties[0].flags |= FLAG_FALLBACK_TO_UDP;
        // Null template instead of the explicit one.
        let mut null_template = exact_family(DohProvider::Cloudflare, false);
        null_template.properties[0].template = None;
        // Unexpected extra entry.
        let mut extra = exact_family(DohProvider::Cloudflare, false);
        extra.servers.push("9.9.9.9".into());
        // Reversed order.
        let mut reversed = exact_family(DohProvider::Cloudflare, false);
        reversed.servers.reverse();
        for (i, family) in [fallback, null_template, extra, reversed].into_iter().enumerate() {
            let mut input = quiet_input();
            input.adapters.push(adapter(&format!("g{i}"), Some(family), None));
            let report = detect(&input);
            assert!(
                matches!(report.verdicts[0].class, LegacyClass::AlteredProperty { .. }),
                "variant {i} must be AlteredProperty, got {:?}",
                report.verdicts[0].class
            );
            assert!(matches!(
                request_repair(&report.verdicts[0], Some(&approval())),
                RepairDecision::Refused { .. }
            ));
        }
    }

    #[test]
    fn live_legacy_gui_blocks_everything() {
        let mut input = quiet_input();
        input.listeners.yeager_gui_live = true;
        input.adapters.push(adapter(
            "g1",
            Some(exact_family(DohProvider::Cloudflare, false)),
            None,
        ));
        let report = detect(&input);
        assert_eq!(report.verdicts[0].class, LegacyClass::BlockedLiveOwner);
        assert!(matches!(
            request_repair(&report.verdicts[0], Some(&approval())),
            RepairDecision::Refused { .. }
        ));
    }

    #[test]
    fn other_dns_listener_blocks_everything() {
        let mut input = quiet_input();
        input.listeners.other_dns_listener = true;
        input.adapters.push(adapter(
            "g1",
            Some(exact_family(DohProvider::Cloudflare, false)),
            None,
        ));
        let report = detect(&input);
        assert_eq!(report.verdicts[0].class, LegacyClass::BlockedOtherListener);
        assert!(matches!(
            request_repair(&report.verdicts[0], Some(&approval())),
            RepairDecision::Refused { .. }
        ));
    }

    #[test]
    fn exact_shape_without_properties_is_ambiguous() {
        // Effective-list-only evidence cannot see DoH templates/flags, so
        // an exact-shaped server list without properties must never read
        // as an exact candidate.
        let mut exact = exact_family(DohProvider::Cloudflare, false);
        exact.properties.clear();
        let mut input = quiet_input();
        input.adapters.push(adapter("g1", Some(exact), None));
        let report = detect(&input);
        assert_eq!(report.verdicts[0].class, LegacyClass::AmbiguousLoopbackOnly);
        assert!(matches!(
            request_repair(&report.verdicts[0], Some(&approval())),
            RepairDecision::Refused { .. }
        ));
    }

    #[test]
    fn unrelated_ordinary_dns_is_not_legacy() {
        let mut input = quiet_input();
        input.adapters.push(adapter(
            "g1",
            Some(FamilyConfig {
                servers: Vec::new(),
                properties: Vec::new(),
            }),
            None,
        ));
        let report = detect(&input);
        assert_eq!(report.verdicts[0].class, LegacyClass::NotLegacy);
    }

    // ---- Q3 approval gate -----------------------------------------------

    fn approval() -> ElevatedApproval {
        ElevatedApproval {
            elevated: true,
            warned_statics_lost: true,
            approver: "operator@console".into(),
        }
    }

    fn exact_verdict() -> AdapterVerdict {
        AdapterVerdict {
            guid: "g1".into(),
            class: LegacyClass::ExactCandidate {
                provider: DohProvider::Cloudflare,
                families: vec!["ipv4".into()],
            },
            detail: "exact".into(),
        }
    }

    #[test]
    fn repair_without_approval_is_refused() {
        assert!(matches!(
            request_repair(&exact_verdict(), None),
            RepairDecision::Refused { .. }
        ));
    }

    #[test]
    fn repair_without_elevation_or_warning_is_refused() {
        assert!(matches!(
            request_repair(
                &exact_verdict(),
                Some(&ElevatedApproval {
                    elevated: false,
                    ..approval()
                })
            ),
            RepairDecision::Refused { .. }
        ));
        assert!(matches!(
            request_repair(
                &exact_verdict(),
                Some(&ElevatedApproval {
                    warned_statics_lost: false,
                    ..approval()
                })
            ),
            RepairDecision::Refused { .. }
        ));
        assert!(matches!(
            request_repair(
                &exact_verdict(),
                Some(&ElevatedApproval {
                    approver: "  ".into(),
                    ..approval()
                })
            ),
            RepairDecision::Refused { .. }
        ));
    }

    #[test]
    fn approved_repair_warns_statics_lost_and_targets_automatic() {
        let decision = request_repair(&exact_verdict(), Some(&approval()));
        let RepairDecision::ApprovedClear { guid, families, warning } = decision else {
            panic!("must approve, got {decision:?}");
        };
        assert_eq!(guid, "g1");
        assert_eq!(families, vec!["ipv4".to_string()]);
        assert!(warning.contains("cannot be reconstructed") || warning.contains("not recorded"));
        // Crash resume: the automatic target, never the dead loopback.
        assert_eq!(resume_target_after_crash(), RepairTarget::Automatic);
    }

    #[test]
    fn approved_intent_is_recorded_and_replayed_as_automatic() {
        // Item 6: crash-resume replays the recorded intent instead of the
        // dead loopback. Record an approved repair, drop everything (the
        // crash), then replay from disk.
        let dir = std::env::temp_dir().join(format!(
            "yeager-legacy-intent-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        record_repair_intent(&dir, "g1", &["ipv4".to_string()]).expect("record intent");
        // Simulate the crash: no in-memory state survives, only the file.
        let replayed = replay_repair_intent(&dir).expect("intent replays after crash");
        assert_eq!(replayed.0, "g1");
        assert_eq!(replayed.1, vec!["ipv4".to_string()]);
        assert_eq!(replayed.2, RepairTarget::Automatic);
        // The resume target is always automatic, never the dead loopback.
        assert_eq!(resume_target_after_crash(), RepairTarget::Automatic);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            replay_repair_intent(&dir).is_none(),
            "no intent means no replay"
        );
    }

    #[test]
    fn repair_description_never_claims_original_restoration() {
        // The approved path must never call its result an original
        // restoration: the statics are lost. Denials ("not restored")
        // are the honest wording and are required.
        let text = describe_repair("g1", &["ipv4".to_string()]);
        let lowered = text.to_lowercase();
        assert!(!lowered.contains("original"), "must not claim original restoration: {text}");
        assert!(
            !lowered.contains("restored the original") && !lowered.contains("original restored"),
            "must not claim original restoration: {text}"
        );
        assert!(lowered.contains("not restored"), "must state plainly that nothing was restored: {text}");
        assert!(lowered.contains("best-effort") || lowered.contains("best effort"));
        assert!(lowered.contains("automatic"));
        assert!(warning_text_has_no_original_claim(&statics_lost_warning()));
    }

    fn warning_text_has_no_original_claim(warning: &str) -> bool {
        let lowered = warning.to_lowercase();
        // The warning explains loss; it must not promise restoration.
        !(lowered.contains("will be restored") || lowered.contains("original configuration restored"))
    }
}
