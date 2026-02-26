use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::header::{ETAG, HeaderValue, IF_NONE_MATCH};
use actix_web::{Error, HttpResponse};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use std::rc::Rc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSensitivity {
    Sensitive,
    NonSensitive,
}

pub fn cache_headers(sensitivity: CacheSensitivity) -> Vec<(&'static str, &'static str)> {
    match sensitivity {
        CacheSensitivity::Sensitive => vec![
            ("cache-control", "no-store, max-age=0, must-revalidate"),
            ("pragma", "no-cache"),
        ],
        CacheSensitivity::NonSensitive => {
            vec![("cache-control", "private, max-age=300, must-revalidate")]
        }
    }
}

#[derive(Clone, Default)]
pub struct EtagMiddleware;

pub fn etag() -> EtagMiddleware {
    EtagMiddleware
}

pub fn set_weak_etag(mut response: HttpResponse, value: &str) -> HttpResponse {
    let normalized = if value.starts_with("W/") {
        value.to_string()
    } else {
        format!("W/\"{}\"", value)
    };

    if let Ok(header) = HeaderValue::from_str(&normalized) {
        response.headers_mut().insert(ETAG, header);
    }
    response
}

impl<S, B> Transform<S, ServiceRequest> for EtagMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = EtagMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(EtagMiddlewareService {
            service: Rc::new(service),
        })
    }
}

pub struct EtagMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for EtagMiddlewareService<S>
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
            let req_etag = req
                .headers()
                .get(IF_NONE_MATCH)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let res = service.call(req).await?.map_into_left_body();

            if let Some(inm) = req_etag {
                let matched = res
                    .headers()
                    .get(ETAG)
                    .and_then(|h| h.to_str().ok())
                    .map(|etag| etag == inm)
                    .unwrap_or(false);

                if matched {
                    let (req, orig) = res.into_parts();
                    let mut not_mod = HttpResponse::NotModified();
                    if let Some(etag) = orig.headers().get(ETAG).cloned() {
                        not_mod.insert_header((ETAG, etag));
                    }
                    let final_res =
                        ServiceResponse::new(req, not_mod.finish()).map_into_right_body();
                    return Ok(final_res);
                }
            }

            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};

    async fn with_etag() -> HttpResponse {
        set_weak_etag(HttpResponse::Ok().finish(), "abc")
    }

    #[actix_web::test]
    async fn set_weak_etag_writes_header() {
        let res = set_weak_etag(HttpResponse::Ok().finish(), "abc");
        let h = res
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(h, "W/\"abc\"");
    }

    #[actix_web::test]
    async fn etag_middleware_returns_304_on_match() {
        let app = test::init_service(
            App::new()
                .wrap(etag())
                .route("/x", web::get().to(with_etag)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/x")
            .insert_header((IF_NONE_MATCH, "W/\"abc\""))
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), actix_web::http::StatusCode::NOT_MODIFIED);
    }
}
