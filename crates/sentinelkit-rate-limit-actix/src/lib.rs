use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{Error, ResponseError};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use sentinelkit_contract::AppError;
use std::rc::Rc;

#[derive(Clone, Default)]
pub struct NoopRateLimit;

pub fn noop_rate_limit() -> NoopRateLimit {
    NoopRateLimit
}

impl<S, B> Transform<S, ServiceRequest> for NoopRateLimit
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = NoopRateLimitService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(NoopRateLimitService {
            service: Rc::new(service),
        })
    }
}

pub struct NoopRateLimitService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for NoopRateLimitService<S>
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
        Box::pin(async move { service.call(req).await })
    }
}

#[derive(Clone, Default)]
pub struct NormalizeRateLimitErrors;

pub fn normalize_rate_limit_errors() -> NormalizeRateLimitErrors {
    NormalizeRateLimitErrors
}

impl<S, B> Transform<S, ServiceRequest> for NormalizeRateLimitErrors
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = NormalizeRateLimitErrorsService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(NormalizeRateLimitErrorsService {
            service: Rc::new(service),
        })
    }
}

pub struct NormalizeRateLimitErrorsService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for NormalizeRateLimitErrorsService<S>
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
        let service = self.service.clone();
        Box::pin(async move {
            let res = service.call(req).await?;
            if res.status() == actix_web::http::StatusCode::TOO_MANY_REQUESTS {
                let (req, src_res) = res.into_parts();
                let mut std_res = AppError::rate_limited().error_response();

                for (k, v) in src_res.headers() {
                    if k.as_str().starts_with("x-ratelimit")
                        || k == actix_web::http::header::RETRY_AFTER
                    {
                        std_res.headers_mut().insert(k.clone(), v.clone());
                    }
                }

                return Ok(ServiceResponse::new(req, std_res).map_into_right_body());
            }

            Ok(res.map_into_left_body())
        })
    }
}

#[cfg(feature = "rate-limiter-backend")]
pub use rate_limiter::{GlobalIpStrategy, MethodScope, PolicySpec, RateLimiter, RouteRule, global};

#[cfg(feature = "rate-limiter-backend")]
pub fn adaptive_rate_limiter(
    policies: Vec<rate_limiter::PolicySpec>,
    rules: Vec<rate_limiter::RouteRule>,
) -> rate_limiter::RateLimiter {
    rate_limiter::RateLimiter::new(policies, rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};

    async fn too_many() -> HttpResponse {
        HttpResponse::TooManyRequests()
            .insert_header((actix_web::http::header::RETRY_AFTER, "3"))
            .insert_header(("x-ratelimit-level", "L2"))
            .finish()
    }

    #[actix_web::test]
    async fn normalize_429_to_contract_error() {
        let app = test::init_service(
            App::new()
                .wrap(normalize_rate_limit_errors())
                .route("/x", web::get().to(too_many)),
        )
        .await;

        let req = test::TestRequest::get().uri("/x").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), actix_web::http::StatusCode::TOO_MANY_REQUESTS);
        assert!(res.headers().contains_key("x-ratelimit-level"));
        assert!(res.headers().contains_key(actix_web::http::header::RETRY_AFTER));
    }
}
