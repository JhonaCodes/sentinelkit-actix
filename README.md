# sentinelkit-actix

Reusable security and API contract toolkit for `actix-web`.

## Crates

- `sentinelkit-actix`: facade crate (re-exports)
- `sentinelkit-contract`: typed errors and success responses
- `sentinelkit-context`: request context middleware (`x-request-id`)
- `sentinelkit-policy`: endpoint control matrix + compliance validation
- `sentinelkit-cache`: ETag middleware + cache helpers
- `sentinelkit-security-core`: security headers + auth/signing/anti-replay middleware hooks
- `sentinelkit-advanced`: JWE/CBT/Attestation/HBK/Enclave middleware hooks
- `sentinelkit-rate-limit-actix`: rate limit adapter + 429 normalization

## Quick usage

```rust
use actix_web::{web, App, HttpRequest, HttpServer};
use sentinelkit_actix::{context, ok, AppError, ResponseContext};

async fn health(req: HttpRequest) -> Result<actix_web::HttpResponse, AppError> {
    let ctx = sentinelkit_actix::read_request_context(&req)
        .ok_or_else(AppError::internal)?;

    Ok(ok(
        ResponseContext {
            request_id: &ctx.request_id,
            path: &ctx.path,
        },
        serde_json::json!({"status":"ok"}),
    ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(context())
            .route("/v1/health", web::get().to(health))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

## Notes

- Use enums (`ErrorCode`, `I18nKey`) in handlers. Avoid string literals.
- `sentinelkit-rate-limit-actix` composes your external `rate_limiter` library
  through feature `rate-limiter-backend`.
- `sentinelkit-security-core` currently provides middleware hooks with traits,
  so each service can plug concrete verifiers/stores.
