use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{Error, ResponseError};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use sentinelkit_contract::AppError;
use std::rc::Rc;
use std::sync::Arc;

pub trait JweVerifier: Send + Sync + 'static {
    fn verify(&self, req: &ServiceRequest) -> bool;
}

pub trait CbtVerifier: Send + Sync + 'static {
    fn verify(&self, req: &ServiceRequest) -> bool;
}

pub trait AttestationVerifier: Send + Sync + 'static {
    fn verify(&self, req: &ServiceRequest) -> bool;
}

pub trait HardwareKeyVerifier: Send + Sync + 'static {
    fn verify(&self, req: &ServiceRequest) -> bool;
}

pub trait EnclaveVerifier: Send + Sync + 'static {
    fn verify(&self, req: &ServiceRequest) -> bool;
}

fn request_id(req: &ServiceRequest) -> String {
    req.headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("req_unknown")
        .to_string()
}

macro_rules! guarded_middleware {
    ($mw:ident, $svc:ident, $fn_name:ident, $trait_name:ident, $err_expr:expr) => {
        #[derive(Clone)]
        pub struct $mw {
            verifier: Arc<dyn $trait_name>,
        }

        pub fn $fn_name(verifier: Arc<dyn $trait_name>) -> $mw {
            $mw { verifier }
        }

        impl<S, B> Transform<S, ServiceRequest> for $mw
        where
            S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
            S::Future: 'static,
            B: 'static,
        {
            type Response = ServiceResponse<EitherBody<B>>;
            type Error = Error;
            type InitError = ();
            type Transform = $svc<S>;
            type Future = Ready<Result<Self::Transform, Self::InitError>>;

            fn new_transform(&self, service: S) -> Self::Future {
                ok($svc {
                    service: Rc::new(service),
                    verifier: self.verifier.clone(),
                })
            }
        }

        pub struct $svc<S> {
            service: Rc<S>,
            verifier: Arc<dyn $trait_name>,
        }

        impl<S, B> Service<ServiceRequest> for $svc<S>
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
                        let res = $err_expr
                            .with_context(request_id(&req), req.path().to_string())
                            .error_response();
                        return Ok(req.into_response(res).map_into_right_body());
                    }
                    let res = service.call(req).await?.map_into_left_body();
                    Ok(res)
                })
            }
        }
    };
}

guarded_middleware!(
    JweMiddleware,
    JweMiddlewareService,
    jwe,
    JweVerifier,
    AppError::unauthorized()
);
guarded_middleware!(
    CbtMiddleware,
    CbtMiddlewareService,
    cbt,
    CbtVerifier,
    AppError::unauthorized()
);
guarded_middleware!(
    AttestationMiddleware,
    AttestationMiddlewareService,
    attestation,
    AttestationVerifier,
    AppError::forbidden()
);
guarded_middleware!(
    HardwareKeyMiddleware,
    HardwareKeyMiddlewareService,
    hardware_keys,
    HardwareKeyVerifier,
    AppError::unauthorized()
);
guarded_middleware!(
    EnclaveMiddleware,
    EnclaveMiddlewareService,
    enclave,
    EnclaveVerifier,
    AppError::conflict()
);

pub struct HeaderJweVerifier;
impl JweVerifier for HeaderJweVerifier {
    fn verify(&self, req: &ServiceRequest) -> bool {
        let ct_ok = req
            .headers()
            .get(actix_web::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("application/jose"))
            .unwrap_or(false);

        let marker_ok = req
            .headers()
            .get("x-jwe")
            .and_then(|h| h.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        ct_ok || marker_ok
    }
}

pub struct HeaderCbtVerifier;
impl CbtVerifier for HeaderCbtVerifier {
    fn verify(&self, req: &ServiceRequest) -> bool {
        let token_binding = req
            .headers()
            .get("x-token-binding")
            .and_then(|h| h.to_str().ok());
        let cert_fp = req
            .headers()
            .get("x-client-cert-sha256")
            .and_then(|h| h.to_str().ok());

        match (token_binding, cert_fp) {
            (Some(tb), Some(fp)) => tb == fp && !tb.is_empty(),
            _ => false,
        }
    }
}

pub struct HeaderAttestationVerifier;
impl AttestationVerifier for HeaderAttestationVerifier {
    fn verify(&self, req: &ServiceRequest) -> bool {
        req.headers()
            .get("x-aula-attestation")
            .and_then(|h| h.to_str().ok())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    }
}

pub struct HeaderHardwareKeyVerifier;
impl HardwareKeyVerifier for HeaderHardwareKeyVerifier {
    fn verify(&self, req: &ServiceRequest) -> bool {
        let key_id = req
            .headers()
            .get("x-aula-key-id")
            .and_then(|h| h.to_str().ok())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let sig = req
            .headers()
            .get("x-aula-signature")
            .and_then(|h| h.to_str().ok())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let alg = req
            .headers()
            .get("x-aula-alg")
            .and_then(|h| h.to_str().ok())
            .map(|v| matches!(v, "ES256" | "RS256"))
            .unwrap_or(false);

        key_id && sig && alg
    }
}

pub struct HeaderEnclaveVerifier;
impl EnclaveVerifier for HeaderEnclaveVerifier {
    fn verify(&self, req: &ServiceRequest) -> bool {
        req.headers()
            .get("x-enclave-attested")
            .and_then(|h| h.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false)
    }
}

pub struct AllowAllJwe;
impl JweVerifier for AllowAllJwe {
    fn verify(&self, _req: &ServiceRequest) -> bool {
        true
    }
}

pub struct AllowAllCbt;
impl CbtVerifier for AllowAllCbt {
    fn verify(&self, _req: &ServiceRequest) -> bool {
        true
    }
}

pub struct AllowAllAttestation;
impl AttestationVerifier for AllowAllAttestation {
    fn verify(&self, _req: &ServiceRequest) -> bool {
        true
    }
}

pub struct AllowAllHardwareKey;
impl HardwareKeyVerifier for AllowAllHardwareKey {
    fn verify(&self, _req: &ServiceRequest) -> bool {
        true
    }
}

pub struct AllowAllEnclave;
impl EnclaveVerifier for AllowAllEnclave {
    fn verify(&self, _req: &ServiceRequest) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};

    async fn ok_handler() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[actix_web::test]
    async fn jwe_header_verifier_blocks_without_header() {
        let app = test::init_service(
            App::new()
                .wrap(jwe(Arc::new(HeaderJweVerifier)))
                .route("/x", web::get().to(ok_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/x").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn cbt_header_verifier_allows_when_binding_matches() {
        let app = test::init_service(
            App::new()
                .wrap(cbt(Arc::new(HeaderCbtVerifier)))
                .route("/x", web::get().to(ok_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/x")
            .insert_header(("x-token-binding", "abc"))
            .insert_header(("x-client-cert-sha256", "abc"))
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), actix_web::http::StatusCode::OK);
    }
}
