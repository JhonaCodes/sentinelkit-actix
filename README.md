# sentinelkit-actix

Toolkit reusable para contrato API y seguridad en `actix-web`.

## Objetivo

Estandarizar en cualquier API:

- respuestas `success/error` con `meta`
- `request_id` y contexto de request
- middlewares de seguridad por capas
- policy/compliance por endpoint
- cache/etag
- seguridad avanzada (JWE/CBT/Attestation/HBK/Enclave)
- rate limiting con normalizacion de `429`

## Crates

- `sentinelkit-actix`: facade (re-exports)
- `sentinelkit-contract`: `AppError`, `ErrorCode`, `I18nKey`, `Response`, helpers de respuesta
- `sentinelkit-context`: middleware `context()` y lectura de `RequestContext`
- `sentinelkit-policy`: `EndpointProfile`, `PolicyRegistry`, `ControlEvidence`, compliance report
- `sentinelkit-cache`: `etag()`, `set_weak_etag(...)`, `cache_headers(...)`
- `sentinelkit-security-core`: `security_headers`, `authn`, `authz`, `request_signing`, `anti_replay`
- `sentinelkit-advanced`: `jwe`, `cbt`, `attestation`, `hardware_keys`, `enclave`
- `sentinelkit-rate-limit-actix`: adapter rate-limit + `normalize_rate_limit_errors()`

## Instalacion

En tu `Cargo.toml` de servicio:

```toml
[dependencies]
actix-web = "4.13"
serde_json = "1"
sentinelkit-actix = { path = "../sentinelkit-actix/crates/sentinelkit-actix" }
```

Para usar backend real de `rate_limiter`:

```toml
[dependencies]
sentinelkit-actix = {
  path = "../sentinelkit-actix/crates/sentinelkit-actix",
  features = ["rate-limiter-backend"]
}
```

## 1) Respuestas (formas de uso)

### A. Forma directa con `Response::*` (recomendada)

```rust
use sentinelkit_actix::{Response, ResponseContext};

let res = Response::ok_with(
    serde_json::json!({"status":"ok"}),
    ResponseContext { request_id: "req_1", path: "/v1/health" },
);
```

### B. Forma paginada para listados

```rust
use sentinelkit_actix::{Response, ResponseContext};

let hotels = vec![
    serde_json::json!({"id":"htl_1","name":"Hotel Aurora"}),
    serde_json::json!({"id":"htl_2","name":"Hotel Pacific"}),
];

let res = Response::ok_paginated_with(
    hotels,
    1,   // page
    20,  // page_size
    42,  // total_items
    ResponseContext { request_id: "req_2", path: "/v1/hotels" },
);
```

### C. Forma fluida sobre `Result<T, AppError>`

```rust
use sentinelkit_actix::{ResultResponseExt, ResponseContext, AppError};

let payload: Result<serde_json::Value, AppError> = Ok(serde_json::json!({"ok":true}));
let res = payload.ok_with(ResponseContext { request_id: "req_3", path: "/v1/x" })?;
```

### D. Helpers base (compatibilidad)

```rust
use sentinelkit_actix::{ok, created, no_content, not_modified, ResponseContext};

let _ = ok(ResponseContext { request_id: "req_4", path: "/v1/a" }, serde_json::json!({"a":1}));
let _ = created(ResponseContext { request_id: "req_5", path: "/v1/b" }, serde_json::json!({"id":"b1"}));
let _ = no_content(ResponseContext { request_id: "req_6", path: "/v1/c" });
let _ = not_modified("W/\"etag-v1\"");
```

## 2) Errores tipados

### A. Errores estandar

```rust
use sentinelkit_actix::{AppError, ErrorCode, I18nKey, detail};

let err = AppError::validation()
    .with_i18n(I18nKey::ErrorsValidationError)
    .with_detail(detail(
        "email",
        ErrorCode::InvalidFormat,
        Some(I18nKey::ErrorsInvalidFormat),
    ))
    .with_context("req_10", "/v1/hotels");
```

### B. Errores custom (sin tocar core)

```rust
use sentinelkit_actix::{AppError, ErrorCode, I18nKey, detail};

let err = AppError::custom("HOTEL_NOT_AVAILABLE")
    .with_i18n(I18nKey::custom("errors.hotel.not_available"))
    .with_detail(detail(
        "hotel_id",
        ErrorCode::custom("HOTEL_NOT_AVAILABLE"),
        Some(I18nKey::custom("errors.hotel.not_available")),
    ));
```

## 3) Contexto de request

```rust
use actix_web::{App, HttpRequest, HttpResponse, web};
use sentinelkit_actix::{context, read_request_context};

async fn handler(req: HttpRequest) -> HttpResponse {
    let ctx = read_request_context(&req).expect("context");
    HttpResponse::Ok()
        .insert_header(("x-debug-request-id", ctx.request_id))
        .finish()
}

let app = App::new()
    .wrap(context())
    .route("/v1/x", web::get().to(handler));
```

## 4) Policy y compliance

```rust
use sentinelkit_actix::{
    EndpointProfile, PolicyRegistry, RequiredControl,
    ControlEvidence, validate_compliance,
};

let profile = EndpointProfile::new(
    "GET",
    "/v1/hotels/{id}",
    vec![RequiredControl::Authn, RequiredControl::RateLimit],
);

let registry = PolicyRegistry::new(vec![profile.clone()]);
let matched = registry.profile_for("GET", "/v1/hotels/abc");
assert!(matched.is_some());

let mut evidence = ControlEvidence::new();
evidence.insert(RequiredControl::Authn);
let report = validate_compliance(&profile, &evidence);
assert!(!report.ok); // falta RateLimit
```

## 5) Security core

### A. Security headers

```rust
use sentinelkit_actix::{security_headers, SecurityHeadersPolicy};

let mw = security_headers(SecurityHeadersPolicy::prod());
```

### B. Authn/Authz hooks

```rust
use actix_web::dev::ServiceRequest;
use sentinelkit_actix::{
    AuthVerifier, Authorizer, AuthzDecision,
    authn, authz,
};

struct JwtVerifier;
impl AuthVerifier for JwtVerifier {
    fn verify(&self, req: &ServiceRequest) -> bool {
        req.headers().contains_key("authorization")
    }
}

struct Rbac;
impl Authorizer for Rbac {
    fn authorize(&self, _req: &ServiceRequest) -> AuthzDecision {
        AuthzDecision::Allow
    }
}

let _authn = authn(std::sync::Arc::new(JwtVerifier));
let _authz = authz(std::sync::Arc::new(Rbac));
```

### C. Request signing y anti-replay hooks

```rust
use actix_web::dev::ServiceRequest;
use sentinelkit_actix::{RequestSigner, AntiReplayStore, request_signing, anti_replay};

struct HmacSigner;
impl RequestSigner for HmacSigner {
    fn verify_signature(&self, req: &ServiceRequest) -> bool {
        req.headers().contains_key("x-aula-signature")
    }
}

struct ReplayStore;
impl AntiReplayStore for ReplayStore {
    fn verify_nonce_and_timestamp(&self, req: &ServiceRequest) -> bool {
        req.headers().contains_key("x-aula-nonce") && req.headers().contains_key("x-aula-timestamp")
    }
}

let _sig = request_signing(std::sync::Arc::new(HmacSigner));
let _replay = anti_replay(std::sync::Arc::new(ReplayStore));
```

## 6) Cache y ETag

```rust
use sentinelkit_actix::{etag, set_weak_etag, cache_headers, CacheSensitivity};
use actix_web::HttpResponse;

let _etag_mw = etag();
let _res = set_weak_etag(HttpResponse::Ok().finish(), "hotels-v10");
let _headers = cache_headers(CacheSensitivity::NonSensitive);
```

## 7) Advanced security

### A. Verificadores listos (header-based)

```rust
use sentinelkit_actix::{
    jwe, cbt, attestation, hardware_keys, enclave,
    HeaderJweVerifier, HeaderCbtVerifier, HeaderAttestationVerifier,
    HeaderHardwareKeyVerifier, HeaderEnclaveVerifier,
};

let _jwe = jwe(std::sync::Arc::new(HeaderJweVerifier));
let _cbt = cbt(std::sync::Arc::new(HeaderCbtVerifier));
let _att = attestation(std::sync::Arc::new(HeaderAttestationVerifier));
let _hbk = hardware_keys(std::sync::Arc::new(HeaderHardwareKeyVerifier));
let _enc = enclave(std::sync::Arc::new(HeaderEnclaveVerifier));
```

### B. Verificador custom

```rust
use actix_web::dev::ServiceRequest;
use sentinelkit_actix::{AttestationVerifier, attestation};

struct MyAttestation;
impl AttestationVerifier for MyAttestation {
    fn verify(&self, req: &ServiceRequest) -> bool {
        req.headers().get("x-aula-attestation").is_some()
    }
}

let _mw = attestation(std::sync::Arc::new(MyAttestation));
```

## 8) Rate limiting

### A. Normalizacion de 429 (si usas cualquier middleware externo)

```rust
use sentinelkit_actix::normalize_rate_limit_errors;

let _normalize = normalize_rate_limit_errors();
```

### B. Integracion real con `JhonaCodes/rate-limiter` (feature)

```rust
#[cfg(feature = "rate-limiter-backend")]
{
    use sentinelkit_actix::{adaptive_rate_limiter, MethodScope, PolicySpec, RouteRule};

    let policies = vec![
        PolicySpec::new("auth", true, 5, 30),
        PolicySpec::new("default", false, 20, 100),
    ];
    let rules = vec![
        RouteRule::new("auth", vec!["/v1/auth/"], MethodScope::Any),
        RouteRule::new("default", vec!["/v1/"], MethodScope::Any),
    ];

    let limiter = adaptive_rate_limiter(policies, rules);
    let _actix_mw = limiter.middleware();
}
```

## 9) Pipeline completo recomendado

```rust
use actix_web::{App, web};
use sentinelkit_actix::*;

let app = App::new()
    .wrap(context())
    .wrap(security_headers(SecurityHeadersPolicy::prod()))
    .wrap(authn(std::sync::Arc::new(AllowAllAuth)))
    .wrap(authz(std::sync::Arc::new(AllowAllAuthorizer)))
    .wrap(request_signing(std::sync::Arc::new(AllowAllSigner)))
    .wrap(anti_replay(std::sync::Arc::new(AllowAllAntiReplay)))
    .wrap(jwe(std::sync::Arc::new(HeaderJweVerifier)))
    .wrap(cbt(std::sync::Arc::new(HeaderCbtVerifier)))
    .wrap(attestation(std::sync::Arc::new(HeaderAttestationVerifier)))
    .wrap(hardware_keys(std::sync::Arc::new(HeaderHardwareKeyVerifier)))
    .wrap(enclave(std::sync::Arc::new(HeaderEnclaveVerifier)))
    .wrap(etag())
    .wrap(normalize_rate_limit_errors())
    .route("/v1/health", web::get().to(|| async { "ok" }));
```

## 10) Tests

Por crate:

```bash
cargo test -p sentinelkit-contract
cargo test -p sentinelkit-context
cargo test -p sentinelkit-policy
cargo test -p sentinelkit-cache
cargo test -p sentinelkit-security-core
cargo test -p sentinelkit-advanced
cargo test -p sentinelkit-rate-limit-actix
```

Test unificado:

```bash
cargo test -p sentinelkit-actix
```

Con `rate-limiter-backend`:

```bash
cargo test -p sentinelkit-actix --features rate-limiter-backend
```
