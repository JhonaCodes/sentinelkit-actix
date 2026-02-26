use std::sync::Arc;

pub use sentinelkit_context::{RequestContext, SentinelContext, context, read_request_context};
pub use sentinelkit_contract::{
    ApiErrorBody, ApiErrorEnvelope, ApiMeta, ApiSuccess, AppError, ErrorCode, ErrorDetail, I18nKey,
    PaginationConfig, PaginationMeta, PaginationNormalized, PaginationQuery, Response,
    ResponseContext, ResultResponseExt, created, detail, no_content, normalize_pagination_query,
    not_modified, ok,
};
pub use sentinelkit_cache::{CacheSensitivity, EtagMiddleware, cache_headers, etag, set_weak_etag};
pub use sentinelkit_policy::{
    ComplianceReport, ControlEvidence, EndpointProfile, PolicyRegistry, RequiredControl,
};
pub use sentinelkit_rate_limit_actix::{
    NoopRateLimit, NormalizeRateLimitErrors, noop_rate_limit, normalize_rate_limit_errors,
};
#[cfg(feature = "rate-limiter-backend")]
pub use sentinelkit_rate_limit_actix::{
    GlobalIpStrategy, MethodScope, PolicySpec, RateLimiter, RouteRule, adaptive_rate_limiter,
    global,
};
pub use sentinelkit_security_core::{
    AllowAllAntiReplay, AllowAllAuth, AllowAllAuthorizer, AllowAllSigner, AntiReplayMiddleware,
    AntiReplayStore, AntiReplayConfig, AuthVerifier, AuthnMiddleware, AuthzDecision,
    AuthzMiddleware, Authorizer, HmacRequestSigner, HmacSigningConfig, InMemoryAntiReplayStore,
    JwtHs256AuthVerifier, JwtHs256Config, RedisAntiReplayStore, RequestSigner,
    RequestSigningMiddleware,
    SecurityHeadersMiddleware, SecurityHeadersPolicy, anti_replay, authn, request_signing,
    authz, security_headers,
};
pub use sentinelkit_advanced::{
    AllowAllAttestation, AllowAllCbt, AllowAllEnclave, AllowAllHardwareKey, AllowAllJwe,
    AttestationMiddleware, AttestationVerifier, CbtMiddleware, CbtVerifier, EnclaveMiddleware,
    EnclaveVerifier, HardwareKeyMiddleware, HardwareKeyVerifier, HeaderAttestationVerifier,
    HeaderCbtVerifier, HeaderEnclaveVerifier, HeaderHardwareKeyVerifier, HeaderJweVerifier,
    JweMiddleware, JweVerifier, JwtHs256AttestationConfig, JwtHs256AttestationVerifier,
    attestation, cbt, enclave, hardware_keys, jwe,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityStateStore {
    InMemory,
    Redis { url: String },
}

#[derive(Debug, Clone)]
pub struct SentinelKitConfig {
    pub state_store: SecurityStateStore,
    pub headers_policy: SecurityHeadersPolicy,
    pub enable_etag: bool,
    pub enable_rate_limit_normalization: bool,
    pub enable_jwe: bool,
    pub enable_cbt: bool,
    pub enable_attestation: bool,
    pub enable_hardware_keys: bool,
    pub enable_enclave: bool,
}

impl Default for SentinelKitConfig {
    fn default() -> Self {
        Self {
            state_store: SecurityStateStore::InMemory,
            headers_policy: SecurityHeadersPolicy::prod(),
            enable_etag: true,
            enable_rate_limit_normalization: true,
            enable_jwe: false,
            enable_cbt: false,
            enable_attestation: false,
            enable_hardware_keys: false,
            enable_enclave: false,
        }
    }
}

pub struct SentinelKitConfigBuilder {
    cfg: SentinelKitConfig,
}

impl SentinelKitConfigBuilder {
    pub fn new() -> Self {
        Self {
            cfg: SentinelKitConfig::default(),
        }
    }

    pub fn in_memory_state(mut self) -> Self {
        self.cfg.state_store = SecurityStateStore::InMemory;
        self
    }

    pub fn redis_state(mut self, url: impl Into<String>) -> Self {
        self.cfg.state_store = SecurityStateStore::Redis { url: url.into() };
        self
    }

    pub fn local_redis(mut self) -> Self {
        self.cfg.state_store = SecurityStateStore::Redis {
            url: "redis://127.0.0.1:6379".to_string(),
        };
        self
    }

    pub fn advanced_all(mut self, enabled: bool) -> Self {
        self.cfg.enable_jwe = enabled;
        self.cfg.enable_cbt = enabled;
        self.cfg.enable_attestation = enabled;
        self.cfg.enable_hardware_keys = enabled;
        self.cfg.enable_enclave = enabled;
        self
    }

    pub fn etag(mut self, enabled: bool) -> Self {
        self.cfg.enable_etag = enabled;
        self
    }

    pub fn rate_limit_normalization(mut self, enabled: bool) -> Self {
        self.cfg.enable_rate_limit_normalization = enabled;
        self
    }

    pub fn build(self) -> SentinelKitConfig {
        self.cfg
    }
}

impl Default for SentinelKitConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct SentinelKitInit {
    pub cfg: SentinelKitConfig,
}

impl SentinelKitInit {
    pub fn from_config(cfg: SentinelKitConfig) -> Self {
        Self { cfg }
    }

    pub fn builder() -> SentinelKitConfigBuilder {
        SentinelKitConfigBuilder::new()
    }

    pub fn default_dev() -> Self {
        Self::from_config(SentinelKitConfig::default())
    }

    pub fn default_prod_local_redis() -> Self {
        Self::from_config(
            SentinelKitConfigBuilder::new()
                .local_redis()
                .advanced_all(true)
                .build(),
        )
    }
}

#[derive(Clone)]
pub struct SentinelKitVerifiers {
    pub auth: Arc<dyn AuthVerifier>,
    pub authz: Arc<dyn Authorizer>,
    pub signer: Arc<dyn RequestSigner>,
    pub anti_replay: Arc<dyn AntiReplayStore>,
    pub jwe: Arc<dyn JweVerifier>,
    pub cbt: Arc<dyn CbtVerifier>,
    pub attestation: Arc<dyn AttestationVerifier>,
    pub hardware_keys: Arc<dyn HardwareKeyVerifier>,
    pub enclave: Arc<dyn EnclaveVerifier>,
}

impl Default for SentinelKitVerifiers {
    fn default() -> Self {
        Self {
            auth: Arc::new(AllowAllAuth),
            authz: Arc::new(AllowAllAuthorizer),
            signer: Arc::new(AllowAllSigner),
            anti_replay: Arc::new(AllowAllAntiReplay),
            jwe: Arc::new(AllowAllJwe),
            cbt: Arc::new(AllowAllCbt),
            attestation: Arc::new(AllowAllAttestation),
            hardware_keys: Arc::new(AllowAllHardwareKey),
            enclave: Arc::new(AllowAllEnclave),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManagedSecurityConfig {
    pub auth_jwt_hs256: Option<JwtHs256Config>,
    pub signing_hmac: Option<HmacSigningConfig>,
    pub anti_replay: Option<AntiReplayConfig>,
    pub attestation_jwt_hs256: Option<JwtHs256AttestationConfig>,
    pub anti_replay_redis_url: Option<String>,
}

impl ManagedSecurityConfig {
    pub fn with_auth_jwt_hs256(mut self, cfg: JwtHs256Config) -> Self {
        self.auth_jwt_hs256 = Some(cfg);
        self
    }

    pub fn with_signing_hmac(mut self, cfg: HmacSigningConfig) -> Self {
        self.signing_hmac = Some(cfg);
        self
    }

    pub fn with_anti_replay(mut self, cfg: AntiReplayConfig) -> Self {
        self.anti_replay = Some(cfg);
        self
    }

    pub fn with_anti_replay_redis(mut self, redis_url: impl Into<String>) -> Self {
        self.anti_replay_redis_url = Some(redis_url.into());
        self
    }

    pub fn with_attestation_jwt_hs256(mut self, cfg: JwtHs256AttestationConfig) -> Self {
        self.attestation_jwt_hs256 = Some(cfg);
        self
    }
}

pub fn managed_verifiers(cfg: ManagedSecurityConfig) -> Result<SentinelKitVerifiers, String> {
    let mut verifiers = SentinelKitVerifiers::default();

    if let Some(auth_cfg) = cfg.auth_jwt_hs256 {
        verifiers.auth = Arc::new(JwtHs256AuthVerifier::new(auth_cfg));
    }

    if let Some(sign_cfg) = cfg.signing_hmac {
        verifiers.signer = Arc::new(HmacRequestSigner::new(sign_cfg));
    }

    let anti_cfg = cfg.anti_replay.unwrap_or_default();
    if let Some(redis_url) = cfg.anti_replay_redis_url {
        let store = RedisAntiReplayStore::new(&redis_url, anti_cfg)
            .map_err(|e| format!("redis anti-replay init error: {e}"))?;
        verifiers.anti_replay = Arc::new(store);
    } else {
        verifiers.anti_replay = Arc::new(InMemoryAntiReplayStore::new(anti_cfg));
    }

    if let Some(att_cfg) = cfg.attestation_jwt_hs256 {
        verifiers.attestation = Arc::new(JwtHs256AttestationVerifier::new(att_cfg));
    }

    Ok(verifiers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_supports_local_redis_and_advanced_toggle() {
        let cfg = SentinelKitInit::builder()
            .local_redis()
            .advanced_all(true)
            .build();

        assert!(matches!(cfg.state_store, SecurityStateStore::Redis { .. }));
        assert!(cfg.enable_jwe);
        assert!(cfg.enable_cbt);
        assert!(cfg.enable_attestation);
        assert!(cfg.enable_hardware_keys);
        assert!(cfg.enable_enclave);
    }

    #[test]
    fn managed_verifiers_in_memory_builds() {
        let cfg = ManagedSecurityConfig::default()
            .with_auth_jwt_hs256(JwtHs256Config {
                secret: "secret".to_string(),
                issuer: "issuer".to_string(),
                audience: "aud".to_string(),
            })
            .with_signing_hmac(HmacSigningConfig {
                secret: "secret".to_string(),
                timestamp_window_secs: 300,
            })
            .with_anti_replay(AntiReplayConfig::default());

        let result = managed_verifiers(cfg);
        assert!(result.is_ok());
    }
}
