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

## Configuracion centralizada (`init` en `main`)

No necesitas \"millones de env vars\". Puedes configurar todo en un solo objeto:

```rust
use sentinelkit_actix::SentinelKitInit;

let init = SentinelKitInit::from_config(
    SentinelKitInit::builder()
        .local_redis()           // usa redis://127.0.0.1:6379
        .advanced_all(true)      // JWE/CBT/Attestation/HBK/Enclave
        .etag(true)
        .rate_limit_normalization(true)
        .build(),
);
```

Presets:

```rust
let dev = SentinelKitInit::default_dev();                  // in-memory
let prod = SentinelKitInit::default_prod_local_redis();    // redis local + advanced on
```

## Managed verifiers (sin `impl` manual)

Si no quieres implementar traits de verificación, usa configuración managed:

```rust
use sentinelkit_actix::*;

let managed = ManagedSecurityConfig::default()
    .with_auth_jwt_hs256(JwtHs256Config {
        secret: "dev-secret".to_string(),
        issuer: "aula-issuer".to_string(),
        audience: "aula-api".to_string(),
    })
    .with_signing_hmac(HmacSigningConfig {
        secret: "signing-secret".to_string(),
        timestamp_window_secs: 300,
    })
    .with_anti_replay(AntiReplayConfig::default())
    .with_anti_replay_redis("redis://127.0.0.1:6379")
    .with_attestation_jwt_hs256(JwtHs256AttestationConfig {
        secret: "attestation-secret".to_string(),
        issuer: "attestation-issuer".to_string(),
        audience: "aula-api".to_string(),
        required_integrity: Some("MEETS_STRONG_INTEGRITY".to_string()),
    });

let verifiers = managed_verifiers(managed).expect("managed verifiers");
```

Esto te da:

- `auth` con JWT HS256
- `signer` con HMAC de request (`method + path + timestamp`)
- `anti_replay` en Redis (o memoria si omites redis)
- `attestation` con JWT HS256
- fallback allow-all en módulos no configurados

## Bootstrap recomendado en `main`

```rust
use actix_web::{App, HttpServer};
use sentinelkit_actix::*;

let init = SentinelKitInit::default_prod_local_redis();
let verifiers = SentinelKitVerifiers::default(); // reemplaza por tus verificadores reales

HttpServer::new(move || {
    let mut app = App::new()
        .wrap(context())
        .wrap(security_headers(init.cfg.headers_policy.clone()))
        .wrap(authn(verifiers.auth.clone()))
        .wrap(authz(verifiers.authz.clone()))
        .wrap(request_signing(verifiers.signer.clone()))
        .wrap(anti_replay(verifiers.anti_replay.clone()));

    if init.cfg.enable_jwe {
        app = app.wrap(jwe(verifiers.jwe.clone()));
    }
    if init.cfg.enable_cbt {
        app = app.wrap(cbt(verifiers.cbt.clone()));
    }
    if init.cfg.enable_attestation {
        app = app.wrap(attestation(verifiers.attestation.clone()));
    }
    if init.cfg.enable_hardware_keys {
        app = app.wrap(hardware_keys(verifiers.hardware_keys.clone()));
    }
    if init.cfg.enable_enclave {
        app = app.wrap(enclave(verifiers.enclave.clone()));
    }
    if init.cfg.enable_etag {
        app = app.wrap(etag());
    }
    if init.cfg.enable_rate_limit_normalization {
        app = app.wrap(normalize_rate_limit_errors());
    }

    app
})
```

## Configuración completa por modo

### Modo A: Solo memoria (rápido para dev)

Cuándo usar:

- desarrollo local
- una sola instancia del backend
- no necesitas estado compartido entre réplicas

Config:

```rust
use sentinelkit_actix::*;

let init = SentinelKitInit::from_config(
    SentinelKitInit::builder()
        .in_memory_state()
        .advanced_all(true)          // o false si no quieres módulos avanzados
        .etag(true)
        .rate_limit_normalization(true)
        .build(),
);

let verifiers = SentinelKitVerifiers::default();
```

Limitación:

- si reinicias la app, estado de nonce/idempotency/replay se pierde
- no sirve bien para múltiples instancias

### Modo B: Redis (recomendado para beta/prod)

Cuándo usar:

- múltiples instancias
- necesitas estado compartido de seguridad
- quieres control más robusto de anti-replay/idempotency/rate-state

#### 1) Levantar Redis en tu VM (sin cuenta cloud)

Opción Docker:

```bash
docker run -d --name redis-local -p 6379:6379 redis:7
```

#### 2) Configurar sentinelkit con Redis

```rust
use sentinelkit_actix::*;

let init = SentinelKitInit::from_config(
    SentinelKitInit::builder()
        .redis_state("redis://127.0.0.1:6379")
        // también existe: .local_redis()
        .advanced_all(true)
        .etag(true)
        .rate_limit_normalization(true)
        .build(),
);

let verifiers = SentinelKitVerifiers::default();
```

#### 3) Aplicar pipeline completo en `main`

```rust
use actix_web::{App, HttpServer};
use sentinelkit_actix::*;

let init = SentinelKitInit::builder()
    .redis_state("redis://127.0.0.1:6379")
    .advanced_all(true)
    .etag(true)
    .rate_limit_normalization(true)
    .build();

let init = SentinelKitInit::from_config(init);
let verifiers = managed_verifiers(
    ManagedSecurityConfig::default()
        .with_auth_jwt_hs256(JwtHs256Config {
            secret: "dev-secret".to_string(),
            issuer: "aula-issuer".to_string(),
            audience: "aula-api".to_string(),
        })
        .with_signing_hmac(HmacSigningConfig {
            secret: "signing-secret".to_string(),
            timestamp_window_secs: 300,
        })
        .with_anti_replay(AntiReplayConfig::default())
).expect("managed verifiers");

HttpServer::new(move || {
    let mut app = App::new()
        .wrap(context())
        .wrap(security_headers(init.cfg.headers_policy.clone()))
        .wrap(authn(verifiers.auth.clone()))
        .wrap(authz(verifiers.authz.clone()))
        .wrap(request_signing(verifiers.signer.clone()))
        .wrap(anti_replay(verifiers.anti_replay.clone()));

    if init.cfg.enable_jwe {
        app = app.wrap(jwe(verifiers.jwe.clone()));
    }
    if init.cfg.enable_cbt {
        app = app.wrap(cbt(verifiers.cbt.clone()));
    }
    if init.cfg.enable_attestation {
        app = app.wrap(attestation(verifiers.attestation.clone()));
    }
    if init.cfg.enable_hardware_keys {
        app = app.wrap(hardware_keys(verifiers.hardware_keys.clone()));
    }
    if init.cfg.enable_enclave {
        app = app.wrap(enclave(verifiers.enclave.clone()));
    }
    if init.cfg.enable_etag {
        app = app.wrap(etag());
    }
    if init.cfg.enable_rate_limit_normalization {
        app = app.wrap(normalize_rate_limit_errors());
    }

    app
})
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

### B2. Paginación segura desde query (`?page=&page_size=&sort=`)

```rust
use actix_web::{web::Query, HttpResponse};
use sentinelkit_actix::{
    AppError, PaginationConfig, PaginationQuery, Response, ResponseContext,
    SentinelContext, normalize_pagination_query,
};

async fn list_hotels(ctx: SentinelContext, q: Query<PaginationQuery>) -> Result<HttpResponse, AppError> {
    let pg = normalize_pagination_query(
        q.into_inner(),
        PaginationConfig::default(),
        &["created_at_desc", "name_asc"],
    )?;

    // usa pg.page, pg.page_size, pg.offset, pg.sort en tu repo/DB
    let hotels = vec![serde_json::json!({"id":"htl_1","name":"Hotel Aurora"})];

    Ok(Response::ok_paginated_with(
        hotels,
        pg.page,
        pg.page_size,
        42,
        ResponseContext {
            request_id: ctx.request_id(),
            path: ctx.path(),
        },
    ))
}
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
use actix_web::{web, App, HttpResponse};
use sentinelkit_actix::{context, SentinelContext};

#[derive(Clone)]
struct AppStateService {
    app_name: String,
}

async fn handler(ctx: SentinelContext, state: web::Data<AppStateService>) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("x-debug-request-id", ctx.request_id()))
        .insert_header(("x-app-name", state.app_name.clone()))
        .finish()
}

let app = App::new()
    .app_data(web::Data::new(AppStateService {
        app_name: "hotel-api".to_string(),
    }))
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

Ejemplo ejecutable de referencia (managed config + Actix):

```bash
cargo run -p sentinelkit-actix --example managed_main --features rate-limiter-backend
```

## 11) Variables de entorno (opcionales)

La libreria funciona sin env vars obligatorias.
Si quieres, puedes usar env vars para no hardcodear config.

Ejemplo opcional:

```bash
# Base API
export API_BASE_URL="http://127.0.0.1:8080"

# Authn (JWT/OAuth)
export AUTH_ISSUER="https://issuer.example.com"
export AUTH_AUDIENCE="api://my-service"
export AUTH_JWKS_URL="https://issuer.example.com/.well-known/jwks.json"

# Request signing
export SIGNING_HMAC_SECRET="replace-me"

# Anti-replay
export ANTI_REPLAY_WINDOW_SECS="300"
export REDIS_URL="redis://127.0.0.1:6379"

# Advanced controls
export REQUIRE_JWE="true"
export REQUIRE_CBT="true"
export REQUIRE_ATTESTATION="true"
export REQUIRE_HBK="true"
export REQUIRE_ENCLAVE="true"

# Rate limiter (si usas provider real)
export RATE_LIMIT_ENABLED="true"
```

Notas:

- Si no quieres env vars, usa `SentinelKitInit::builder()` y valores directos.
- `REDIS_URL` no requiere cuenta cloud; puede ser Redis local (`redis://127.0.0.1:6379`).
- En `dev` puedes quedarte en `InMemory` (`default_dev()`).

## 12) Ejemplos de requests HTTP (curl)

### A. Health basico (solo contexto)

```bash
curl -i "$API_BASE_URL/v1/health"
```

Esperado:

- status `200`
- header `x-request-id`

### B. Endpoint con Authn (Bearer)

```bash
curl -i "$API_BASE_URL/v1/hotels" \
  -H "Authorization: Bearer <access_token>"
```

Sin token valido: `401` estandarizado.

### C. Endpoint con request signing (HMAC/JWS hook)

```bash
curl -i "$API_BASE_URL/v1/hotels" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Aula-Signature: <signature>" \
  -H "X-Aula-Alg: HMAC-SHA256"
```

Sin firma valida: `401` estandarizado.

### D. Endpoint con anti-replay

```bash
curl -i "$API_BASE_URL/v1/hotels" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Aula-Nonce: nonce-123" \
  -H "X-Aula-Timestamp: 2026-02-26T21:30:00Z"
```

Nonce/timestamp invalidos o repetidos: `409` estandarizado.

### E. Endpoint con JWE (header-based verifier)

Opcion 1:

```bash
curl -i "$API_BASE_URL/v1/hotels/secure" \
  -H "Content-Type: application/jose" \
  --data '<jwe-compact-payload>'
```

Opcion 2:

```bash
curl -i "$API_BASE_URL/v1/hotels/secure" \
  -H "X-JWE: 1" \
  --data '{}'
```

Si no cumple: `401`.

### F. Endpoint con CBT

```bash
curl -i "$API_BASE_URL/v1/hotels/secure" \
  -H "X-Token-Binding: abc123" \
  -H "X-Client-Cert-SHA256: abc123"
```

Si no coincide binding/cert: `401`.

### G. Endpoint con Attestation

```bash
curl -i "$API_BASE_URL/v1/hotels/secure" \
  -H "X-Aula-Attestation: <attestation_token>"
```

Sin token de attestation: `403`.

### H. Endpoint con Hardware-backed key proof

```bash
curl -i "$API_BASE_URL/v1/hotels/secure" \
  -H "X-Aula-Key-Id: hk_2026_01" \
  -H "X-Aula-Signature: <signature>" \
  -H "X-Aula-Alg: ES256"
```

Fallo de verificacion: `401`.

### I. Endpoint con Enclave attestation flag

```bash
curl -i "$API_BASE_URL/v1/hotels/secure" \
  -H "X-Enclave-Attested: true"
```

Si no esta atestiguado: `409`.

### J. ETag (cache condicional)

Primer request:

```bash
curl -i "$API_BASE_URL/v1/hotels"
```

Reutilizar ETag en condicional:

```bash
curl -i "$API_BASE_URL/v1/hotels" \
  -H 'If-None-Match: W/"flow-v1"'
```

Si no cambio: `304` sin body.

### K. Rate limit normalizado

Cuando el upstream/rate-limiter devuelve `429`, `normalize_rate_limit_errors()` retorna contrato estandar:

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Too many requests. Please retry later."
  },
  "meta": {
    "status": 429,
    "timestamp": "...",
    "request_id": "...",
    "path": "..."
  }
}
```

Y preserva headers:

- `Retry-After`
- `x-ratelimit-*`

## 13) Ejemplo handler final (hotel list)

```rust
use actix_web::{web, HttpResponse};
use sentinelkit_actix::{AppError, Response, ResponseContext, SentinelContext};

#[derive(Clone)]
pub struct AppStateService {
    pub default_page_size: u32,
}

pub async fn list_hotels(
    ctx: SentinelContext,
    state: web::Data<AppStateService>,
) -> Result<HttpResponse, AppError> {

    let hotels = vec![
        serde_json::json!({\"id\":\"htl_1\",\"name\":\"Hotel Aurora\",\"city\":\"Bogota\"}),
        serde_json::json!({\"id\":\"htl_2\",\"name\":\"Hotel Pacific\",\"city\":\"Cali\"}),
    ];

    Ok(Response::ok_paginated_with(
        hotels,
        1,
        state.default_page_size,
        42,
        ResponseContext {
            request_id: ctx.request_id(),
            path: ctx.path(),
        },
    ))
}
```
