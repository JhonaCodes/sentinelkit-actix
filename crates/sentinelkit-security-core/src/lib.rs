use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::{Error, ResponseError};
use chrono::{DateTime, Utc};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use redis::{Client as RedisClient, Connection as RedisConnection};
use serde::Deserialize;
use sentinelkit_contract::AppError;
use sha2::Sha256;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::Arc;

pub trait AuthVerifier: Send + Sync + 'static {
    fn verify(&self, req: &ServiceRequest) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    DenyUnauthorized,
    DenyForbidden,
}

pub trait Authorizer: Send + Sync + 'static {
    fn authorize(&self, req: &ServiceRequest) -> AuthzDecision;
}

pub trait RequestSigner: Send + Sync + 'static {
    fn verify_signature(&self, req: &ServiceRequest) -> bool;
}

pub trait AntiReplayStore: Send + Sync + 'static {
    fn verify_nonce_and_timestamp(&self, req: &ServiceRequest) -> bool;
}

#[derive(Debug, Clone)]
pub struct JwtHs256Config {
    pub secret: String,
    pub issuer: String,
    pub audience: String,
}

#[derive(Debug, Clone)]
pub struct HmacSigningConfig {
    pub secret: String,
    pub timestamp_window_secs: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct AntiReplayConfig {
    pub timestamp_window_secs: i64,
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            timestamp_window_secs: 300,
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtStdClaims {
    #[serde(rename = "exp")]
    _exp: usize,
    #[allow(dead_code)]
    iat: Option<usize>,
    #[serde(rename = "iss")]
    _iss: String,
    #[serde(rename = "aud")]
    _aud: serde_json::Value,
}

fn request_id(req: &ServiceRequest) -> String {
    req.headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("req_unknown")
        .to_string()
}

#[derive(Debug, Clone)]
pub struct SecurityHeadersPolicy {
    pub hsts: &'static str,
    pub x_content_type_options: &'static str,
    pub x_frame_options: &'static str,
    pub referrer_policy: &'static str,
    pub permissions_policy: &'static str,
    pub content_security_policy: &'static str,
}

impl SecurityHeadersPolicy {
    pub fn prod() -> Self {
        Self {
            hsts: "max-age=63072000; includeSubDomains; preload",
            x_content_type_options: "nosniff",
            x_frame_options: "DENY",
            referrer_policy: "no-referrer",
            permissions_policy: "camera=(), microphone=(), geolocation=()",
            content_security_policy: "default-src 'none'",
        }
    }
}

#[derive(Clone)]
pub struct SecurityHeadersMiddleware {
    policy: SecurityHeadersPolicy,
}

pub fn security_headers(policy: SecurityHeadersPolicy) -> SecurityHeadersMiddleware {
    SecurityHeadersMiddleware { policy }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SecurityHeadersMiddlewareService {
            service: Rc::new(service),
            policy: self.policy.clone(),
        })
    }
}

pub struct SecurityHeadersMiddlewareService<S> {
    service: Rc<S>,
    policy: SecurityHeadersPolicy,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let policy = self.policy.clone();
        Box::pin(async move {
            let mut res = service.call(req).await?;
            let headers = res.headers_mut();
            headers.insert(
                HeaderName::from_static("strict-transport-security"),
                HeaderValue::from_static(policy.hsts),
            );
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static(policy.x_content_type_options),
            );
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static(policy.x_frame_options),
            );
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static(policy.referrer_policy),
            );
            headers.insert(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static(policy.permissions_policy),
            );
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_static(policy.content_security_policy),
            );
            Ok(res)
        })
    }
}

#[derive(Clone)]
pub struct AuthnMiddleware {
    verifier: Arc<dyn AuthVerifier>,
}

#[derive(Clone)]
pub struct AuthzMiddleware {
    authorizer: Arc<dyn Authorizer>,
}

pub fn authn(verifier: Arc<dyn AuthVerifier>) -> AuthnMiddleware {
    AuthnMiddleware { verifier }
}

pub fn authz(authorizer: Arc<dyn Authorizer>) -> AuthzMiddleware {
    AuthzMiddleware { authorizer }
}

impl<S, B> Transform<S, ServiceRequest> for AuthnMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthnMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthnMiddlewareService {
            service: Rc::new(service),
            verifier: self.verifier.clone(),
        })
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthzMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthzMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthzMiddlewareService {
            service: Rc::new(service),
            authorizer: self.authorizer.clone(),
        })
    }
}

pub struct AuthnMiddlewareService<S> {
    service: Rc<S>,
    verifier: Arc<dyn AuthVerifier>,
}

pub struct AuthzMiddlewareService<S> {
    service: Rc<S>,
    authorizer: Arc<dyn Authorizer>,
}

impl<S, B> Service<ServiceRequest> for AuthnMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let verifier = self.verifier.clone();
        let service = self.service.clone();
        Box::pin(async move {
            if !verifier.verify(&req) {
                let res = AppError::unauthorized()
                    .with_context(request_id(&req), req.path().to_string())
                    .error_response();
                return Ok(req.into_response(res).map_into_right_body());
            }
            let res = service.call(req).await?.map_into_left_body();
            Ok(res)
        })
    }
}

impl<S, B> Service<ServiceRequest> for AuthzMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let authorizer = self.authorizer.clone();
        let service = self.service.clone();
        Box::pin(async move {
            match authorizer.authorize(&req) {
                AuthzDecision::Allow => {
                    let res = service.call(req).await?.map_into_left_body();
                    Ok(res)
                }
                AuthzDecision::DenyUnauthorized => {
                    let res = AppError::unauthorized()
                        .with_context(request_id(&req), req.path().to_string())
                        .error_response();
                    Ok(req.into_response(res).map_into_right_body())
                }
                AuthzDecision::DenyForbidden => {
                    let res = AppError::forbidden()
                        .with_context(request_id(&req), req.path().to_string())
                        .error_response();
                    Ok(req.into_response(res).map_into_right_body())
                }
            }
        })
    }
}

#[derive(Clone)]
pub struct RequestSigningMiddleware {
    signer: Arc<dyn RequestSigner>,
}

pub fn request_signing(signer: Arc<dyn RequestSigner>) -> RequestSigningMiddleware {
    RequestSigningMiddleware { signer }
}

impl<S, B> Transform<S, ServiceRequest> for RequestSigningMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestSigningMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestSigningMiddlewareService {
            service: Rc::new(service),
            signer: self.signer.clone(),
        })
    }
}

pub struct RequestSigningMiddlewareService<S> {
    service: Rc<S>,
    signer: Arc<dyn RequestSigner>,
}

impl<S, B> Service<ServiceRequest> for RequestSigningMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let signer = self.signer.clone();
        let service = self.service.clone();
        Box::pin(async move {
            if !signer.verify_signature(&req) {
                let res = AppError::unauthorized()
                    .with_context(request_id(&req), req.path().to_string())
                    .error_response();
                return Ok(req.into_response(res).map_into_right_body());
            }
            let res = service.call(req).await?.map_into_left_body();
            Ok(res)
        })
    }
}

#[derive(Clone)]
pub struct AntiReplayMiddleware {
    store: Arc<dyn AntiReplayStore>,
}

pub fn anti_replay(store: Arc<dyn AntiReplayStore>) -> AntiReplayMiddleware {
    AntiReplayMiddleware { store }
}

impl<S, B> Transform<S, ServiceRequest> for AntiReplayMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AntiReplayMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AntiReplayMiddlewareService {
            service: Rc::new(service),
            store: self.store.clone(),
        })
    }
}

pub struct AntiReplayMiddlewareService<S> {
    service: Rc<S>,
    store: Arc<dyn AntiReplayStore>,
}

impl<S, B> Service<ServiceRequest> for AntiReplayMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let store = self.store.clone();
        let service = self.service.clone();
        Box::pin(async move {
            if !store.verify_nonce_and_timestamp(&req) {
                let res = AppError::conflict()
                    .with_context(request_id(&req), req.path().to_string())
                    .error_response();
                return Ok(req.into_response(res).map_into_right_body());
            }
            let res = service.call(req).await?.map_into_left_body();
            Ok(res)
        })
    }
}

pub struct AllowAllAuth;
impl AuthVerifier for AllowAllAuth {
    fn verify(&self, _req: &ServiceRequest) -> bool {
        true
    }
}

pub struct AllowAllSigner;
impl RequestSigner for AllowAllSigner {
    fn verify_signature(&self, _req: &ServiceRequest) -> bool {
        true
    }
}

pub struct AllowAllAuthorizer;
impl Authorizer for AllowAllAuthorizer {
    fn authorize(&self, _req: &ServiceRequest) -> AuthzDecision {
        AuthzDecision::Allow
    }
}

pub struct AllowAllAntiReplay;
impl AntiReplayStore for AllowAllAntiReplay {
    fn verify_nonce_and_timestamp(&self, _req: &ServiceRequest) -> bool {
        true
    }
}

pub struct JwtHs256AuthVerifier {
    cfg: JwtHs256Config,
}

impl JwtHs256AuthVerifier {
    pub fn new(cfg: JwtHs256Config) -> Self {
        Self { cfg }
    }
}

impl AuthVerifier for JwtHs256AuthVerifier {
    fn verify(&self, req: &ServiceRequest) -> bool {
        let token = match req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        {
            Some(t) if !t.trim().is_empty() => t,
            _ => return false,
        };

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.cfg.issuer.as_str()]);
        validation.set_audience(&[self.cfg.audience.as_str()]);
        validation.validate_exp = true;

        decode::<JwtStdClaims>(
            token,
            &DecodingKey::from_secret(self.cfg.secret.as_bytes()),
            &validation,
        )
        .is_ok()
    }
}

type HmacSha256 = Hmac<Sha256>;

pub struct HmacRequestSigner {
    cfg: HmacSigningConfig,
}

impl HmacRequestSigner {
    pub fn new(cfg: HmacSigningConfig) -> Self {
        Self { cfg }
    }
}

impl RequestSigner for HmacRequestSigner {
    fn verify_signature(&self, req: &ServiceRequest) -> bool {
        let signature = match req
            .headers()
            .get("x-aula-signature")
            .and_then(|h| h.to_str().ok())
        {
            Some(s) if !s.trim().is_empty() => s,
            _ => return false,
        };

        let timestamp = match req
            .headers()
            .get("x-aula-timestamp")
            .and_then(|h| h.to_str().ok())
        {
            Some(t) => t,
            _ => return false,
        };

        let dt = match DateTime::parse_from_rfc3339(timestamp) {
            Ok(v) => v.with_timezone(&Utc),
            Err(_) => return false,
        };
        let skew = (Utc::now() - dt).num_seconds().abs();
        if skew > self.cfg.timestamp_window_secs {
            return false;
        }

        let canonical = format!("{}\n{}\n{}", req.method(), req.path(), timestamp);
        let mut mac = match HmacSha256::new_from_slice(self.cfg.secret.as_bytes()) {
            Ok(v) => v,
            Err(_) => return false,
        };
        mac.update(canonical.as_bytes());
        let expected_hex = hex::encode(mac.finalize().into_bytes());

        subtle::ConstantTimeEq::ct_eq(expected_hex.as_bytes(), signature.as_bytes()).into()
    }
}

pub struct InMemoryAntiReplayStore {
    cfg: AntiReplayConfig,
    nonces: Mutex<std::collections::HashMap<String, i64>>,
}

impl InMemoryAntiReplayStore {
    pub fn new(cfg: AntiReplayConfig) -> Self {
        Self {
            cfg,
            nonces: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl AntiReplayStore for InMemoryAntiReplayStore {
    fn verify_nonce_and_timestamp(&self, req: &ServiceRequest) -> bool {
        let nonce = match req
            .headers()
            .get("x-aula-nonce")
            .and_then(|h| h.to_str().ok())
        {
            Some(v) if !v.trim().is_empty() => v.to_string(),
            _ => return false,
        };
        let timestamp = match req
            .headers()
            .get("x-aula-timestamp")
            .and_then(|h| h.to_str().ok())
        {
            Some(v) => v,
            _ => return false,
        };

        let ts = match DateTime::parse_from_rfc3339(timestamp) {
            Ok(v) => v.with_timezone(&Utc).timestamp(),
            Err(_) => return false,
        };
        let now = Utc::now().timestamp();
        if (now - ts).abs() > self.cfg.timestamp_window_secs {
            return false;
        }

        let mut guard = match self.nonces.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        let min_valid = now - self.cfg.timestamp_window_secs;
        guard.retain(|_, seen_at| *seen_at >= min_valid);

        if guard.contains_key(&nonce) {
            return false;
        }
        guard.insert(nonce, now);
        true
    }
}

pub struct RedisAntiReplayStore {
    cfg: AntiReplayConfig,
    conn: Mutex<RedisConnection>,
}

impl RedisAntiReplayStore {
    pub fn new(redis_url: &str, cfg: AntiReplayConfig) -> Result<Self, redis::RedisError> {
        let client = RedisClient::open(redis_url)?;
        let conn = client.get_connection()?;
        Ok(Self {
            cfg,
            conn: Mutex::new(conn),
        })
    }
}

impl AntiReplayStore for RedisAntiReplayStore {
    fn verify_nonce_and_timestamp(&self, req: &ServiceRequest) -> bool {
        let nonce = match req
            .headers()
            .get("x-aula-nonce")
            .and_then(|h| h.to_str().ok())
        {
            Some(v) if !v.trim().is_empty() => v.to_string(),
            _ => return false,
        };
        let timestamp = match req
            .headers()
            .get("x-aula-timestamp")
            .and_then(|h| h.to_str().ok())
        {
            Some(v) => v,
            _ => return false,
        };

        let ts = match DateTime::parse_from_rfc3339(timestamp) {
            Ok(v) => v.with_timezone(&Utc).timestamp(),
            Err(_) => return false,
        };
        let now = Utc::now().timestamp();
        if (now - ts).abs() > self.cfg.timestamp_window_secs {
            return false;
        }

        let key = format!("sentinelkit:nonce:{nonce}");
        let mut conn = match self.conn.lock() {
            Ok(c) => c,
            Err(p) => p.into_inner(),
        };

        let result: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("EX")
            .arg(self.cfg.timestamp_window_secs)
            .arg("NX")
            .query(&mut *conn);

        matches!(result, Ok(Some(ref ok)) if ok == "OK")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};

    async fn ok_handler() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    struct DenyAuth;
    impl AuthVerifier for DenyAuth {
        fn verify(&self, _req: &ServiceRequest) -> bool {
            false
        }
    }

    struct DenyReplay;
    impl AntiReplayStore for DenyReplay {
        fn verify_nonce_and_timestamp(&self, _req: &ServiceRequest) -> bool {
            false
        }
    }

    struct Forbid;
    impl Authorizer for Forbid {
        fn authorize(&self, _req: &ServiceRequest) -> AuthzDecision {
            AuthzDecision::DenyForbidden
        }
    }

    #[actix_web::test]
    async fn security_headers_are_applied() {
        let app = test::init_service(
            App::new()
                .wrap(security_headers(SecurityHeadersPolicy::prod()))
                .route("/x", web::get().to(ok_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/x").to_request();
        let res = test::call_service(&app, req).await;
        assert!(res
            .headers()
            .contains_key(actix_web::http::header::HeaderName::from_static(
                "strict-transport-security"
            )));
    }

    #[actix_web::test]
    async fn authn_denied_returns_401() {
        let app = test::init_service(
            App::new()
                .wrap(authn(Arc::new(DenyAuth)))
                .route("/x", web::get().to(ok_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/x").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn authz_denied_returns_403() {
        let app = test::init_service(
            App::new()
                .wrap(authz(Arc::new(Forbid)))
                .route("/x", web::get().to(ok_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/x").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), actix_web::http::StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn anti_replay_denied_returns_409() {
        let app = test::init_service(
            App::new()
                .wrap(anti_replay(Arc::new(DenyReplay)))
                .route("/x", web::get().to(ok_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/x").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), actix_web::http::StatusCode::CONFLICT);
    }

    #[test]
    fn hmac_signer_rejects_missing_headers() {
        let signer = HmacRequestSigner::new(HmacSigningConfig {
            secret: "secret".to_string(),
            timestamp_window_secs: 300,
        });
        let req = actix_web::test::TestRequest::get().to_srv_request();
        assert!(!signer.verify_signature(&req));
    }

    #[test]
    fn in_memory_anti_replay_rejects_reused_nonce() {
        let store = InMemoryAntiReplayStore::new(AntiReplayConfig::default());
        let ts = Utc::now().to_rfc3339();
        let req1 = actix_web::test::TestRequest::get()
            .insert_header(("x-aula-nonce", "abc"))
            .insert_header(("x-aula-timestamp", ts.clone()))
            .to_srv_request();
        let req2 = actix_web::test::TestRequest::get()
            .insert_header(("x-aula-nonce", "abc"))
            .insert_header(("x-aula-timestamp", ts))
            .to_srv_request();
        assert!(store.verify_nonce_and_timestamp(&req1));
        assert!(!store.verify_nonce_and_timestamp(&req2));
    }
}
