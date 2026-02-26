use actix_web::{App, HttpRequest, HttpResponse, test, web};
use sentinelkit_advanced::{
    HeaderAttestationVerifier, HeaderCbtVerifier, HeaderEnclaveVerifier, HeaderHardwareKeyVerifier,
    HeaderJweVerifier,
};
use sentinelkit_actix::{
    SecurityHeadersPolicy, anti_replay, attestation, authn, authz, cbt, context, enclave, etag,
    hardware_keys, jwe, ok, request_signing, security_headers, set_weak_etag, AllowAllAntiReplay,
    AllowAllAuth, AllowAllAuthorizer, AllowAllSigner, ResponseContext,
};
use std::sync::Arc;

async fn ok_handler(req: HttpRequest) -> HttpResponse {
    let ctx = sentinelkit_actix::read_request_context(&req).expect("request context");
    let res = ok(
        ResponseContext {
            request_id: &ctx.request_id,
            path: &ctx.path,
        },
        serde_json::json!({"status":"ok"}),
    );
    set_weak_etag(res, "flow-v1")
}

#[actix_web::test]
async fn unified_pipeline_allows_valid_request() {
    let app = test::init_service(
        App::new()
            .wrap(context())
            .wrap(security_headers(SecurityHeadersPolicy::prod()))
            .wrap(authn(Arc::new(AllowAllAuth)))
            .wrap(authz(Arc::new(AllowAllAuthorizer)))
            .wrap(request_signing(Arc::new(AllowAllSigner)))
            .wrap(anti_replay(Arc::new(AllowAllAntiReplay)))
            .wrap(jwe(Arc::new(HeaderJweVerifier)))
            .wrap(cbt(Arc::new(HeaderCbtVerifier)))
            .wrap(attestation(Arc::new(HeaderAttestationVerifier)))
            .wrap(hardware_keys(Arc::new(HeaderHardwareKeyVerifier)))
            .wrap(enclave(Arc::new(HeaderEnclaveVerifier)))
            .wrap(etag())
            .route("/v1/health", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/v1/health")
        .insert_header(("x-jwe", "1"))
        .insert_header(("x-token-binding", "fp"))
        .insert_header(("x-client-cert-sha256", "fp"))
        .insert_header(("x-aula-attestation", "att-token"))
        .insert_header(("x-aula-key-id", "kid-1"))
        .insert_header(("x-aula-signature", "sig"))
        .insert_header(("x-aula-alg", "ES256"))
        .insert_header(("x-enclave-attested", "true"))
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), actix_web::http::StatusCode::OK);
    assert!(res.headers().contains_key("x-request-id"));
    assert!(res.headers().contains_key(actix_web::http::header::ETAG));
}

#[actix_web::test]
async fn unified_pipeline_blocks_when_attestation_missing() {
    let app = test::init_service(
        App::new()
            .wrap(context())
            .wrap(authn(Arc::new(AllowAllAuth)))
            .wrap(authz(Arc::new(AllowAllAuthorizer)))
            .wrap(request_signing(Arc::new(AllowAllSigner)))
            .wrap(anti_replay(Arc::new(AllowAllAntiReplay)))
            .wrap(attestation(Arc::new(HeaderAttestationVerifier)))
            .route("/v1/health", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get().uri("/v1/health").to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), actix_web::http::StatusCode::FORBIDDEN);
}
