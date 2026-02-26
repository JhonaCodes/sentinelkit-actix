use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequiredControl {
    ErrorStd,
    SuccessStd,
    Audit,
    Authn,
    Authz,
    RequestSigning,
    AntiReplay,
    RateLimit,
    Etag,
    Jwe,
    Cbt,
    Attestation,
    HardwareBackedKeys,
    Enclave,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointProfile {
    pub method: String,
    pub path_pattern: String,
    pub required: Vec<RequiredControl>,
}

impl EndpointProfile {
    pub fn new(
        method: impl Into<String>,
        path_pattern: impl Into<String>,
        required: Vec<RequiredControl>,
    ) -> Self {
        Self {
            method: method.into().to_uppercase(),
            path_pattern: path_pattern.into(),
            required,
        }
    }

    pub fn matches(&self, method: &str, path: &str) -> bool {
        let method_match = self.method == "*" || self.method.eq_ignore_ascii_case(method);
        if !method_match {
            return false;
        }

        if self.path_pattern.ends_with("*") {
            let prefix = self.path_pattern.trim_end_matches('*');
            return path.starts_with(prefix);
        }

        if self.path_pattern.contains("{") && self.path_pattern.contains("}") {
            let lhs: Vec<&str> = self.path_pattern.split('/').filter(|s| !s.is_empty()).collect();
            let rhs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if lhs.len() != rhs.len() {
                return false;
            }
            for (a, b) in lhs.iter().zip(rhs.iter()) {
                if a.starts_with('{') && a.ends_with('}') {
                    continue;
                }
                if a != b {
                    return false;
                }
            }
            return true;
        }

        self.path_pattern == path
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyRegistry {
    profiles: Vec<EndpointProfile>,
}

impl PolicyRegistry {
    pub fn new(profiles: Vec<EndpointProfile>) -> Self {
        Self { profiles }
    }

    pub fn push(&mut self, profile: EndpointProfile) {
        self.profiles.push(profile);
    }

    pub fn profile_for(&self, method: &str, path: &str) -> Option<&EndpointProfile> {
        self.profiles.iter().find(|p| p.matches(method, path))
    }

    pub fn required_controls_for(&self, method: &str, path: &str) -> Option<Vec<RequiredControl>> {
        self.profile_for(method, path).map(|p| p.required.clone())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ControlEvidence {
    controls: HashSet<RequiredControl>,
}

impl ControlEvidence {
    pub fn new() -> Self {
        Self {
            controls: HashSet::new(),
        }
    }

    pub fn insert(&mut self, control: RequiredControl) {
        self.controls.insert(control);
    }

    pub fn contains(&self, control: RequiredControl) -> bool {
        self.controls.contains(&control)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceReport {
    pub ok: bool,
    pub missing: Vec<RequiredControl>,
}

pub fn validate_compliance(profile: &EndpointProfile, evidence: &ControlEvidence) -> ComplianceReport {
    let missing: Vec<RequiredControl> = profile
        .required
        .iter()
        .copied()
        .filter(|control| !evidence.contains(*control))
        .collect();

    ComplianceReport {
        ok: missing.is_empty(),
        missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_pattern_with_param_matches_path() {
        let p = EndpointProfile::new("GET", "/v1/students/{id}", vec![RequiredControl::Authn]);
        assert!(p.matches("GET", "/v1/students/abc"));
        assert!(!p.matches("POST", "/v1/students/abc"));
    }

    #[test]
    fn compliance_detects_missing_controls() {
        let p = EndpointProfile::new(
            "GET",
            "/v1/students/{id}",
            vec![RequiredControl::Authn, RequiredControl::RateLimit],
        );
        let mut ev = ControlEvidence::new();
        ev.insert(RequiredControl::Authn);
        let report = validate_compliance(&p, &ev);
        assert!(!report.ok);
        assert_eq!(report.missing, vec![RequiredControl::RateLimit]);
    }
}
