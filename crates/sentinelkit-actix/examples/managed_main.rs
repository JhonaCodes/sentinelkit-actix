use actix_web::{middleware::Condition, web, App, HttpResponse, HttpServer};
use sentinelkit_actix::{
    anti_replay, authn, authz, context, etag, normalize_pagination_query,
    normalize_rate_limit_errors, request_signing, security_headers, AppError,
    AntiReplayConfig, HmacSigningConfig, JwtHs256Config, ManagedSecurityConfig,
    PaginationConfig, PaginationQuery, Response, ResponseContext, SentinelContext,
    SentinelKitInit, managed_verifiers,
};

#[derive(Clone)]
struct AppStateService {
    default_page_size: u32,
}

async fn health(ctx: SentinelContext) -> Result<HttpResponse, AppError> {
    Ok(Response::ok_with(
        serde_json::json!({"status": "ok"}),
        ResponseContext {
            request_id: ctx.request_id(),
            path: ctx.path(),
        },
    ))
}

async fn list_hotels(
    ctx: SentinelContext,
    state: web::Data<AppStateService>,
    q: web::Query<PaginationQuery>,
) -> Result<HttpResponse, AppError> {
    let pg = normalize_pagination_query(
        q.into_inner(),
        PaginationConfig {
            default_page: 1,
            default_page_size: state.default_page_size,
            max_page_size: 100,
        },
        &["created_at_desc", "name_asc"],
    )?;

    let hotels = vec![
        serde_json::json!({"id":"htl_1","name":"Hotel Aurora","city":"Bogota"}),
        serde_json::json!({"id":"htl_2","name":"Hotel Pacific","city":"Cali"}),
    ];

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let init = SentinelKitInit::from_config(
        SentinelKitInit::builder()
            .in_memory_state()
            .advanced_all(false)
            .etag(true)
            .rate_limit_normalization(true)
            .build(),
    );

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
        .with_anti_replay(AntiReplayConfig::default());

    let verifiers = managed_verifiers(managed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppStateService {
                default_page_size: 20,
            }))
            .wrap(context())
            .wrap(security_headers(init.cfg.headers_policy.clone()))
            .wrap(authn(verifiers.auth.clone()))
            .wrap(authz(verifiers.authz.clone()))
            .wrap(request_signing(verifiers.signer.clone()))
            .wrap(anti_replay(verifiers.anti_replay.clone()))
            .wrap(Condition::new(init.cfg.enable_etag, etag()))
            .wrap(Condition::new(
                init.cfg.enable_rate_limit_normalization,
                normalize_rate_limit_errors(),
            ))
            .route("/v1/health", web::get().to(health))
            .route("/v1/hotels", web::get().to(list_hotels))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
