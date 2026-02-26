use actix_web::Error;
use actix_web::HttpMessage;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::header::{HeaderName, HeaderValue};
use chrono::Utc;
use futures_util::future::{LocalBoxFuture, Ready, ok};
use serde::Serialize;
use std::rc::Rc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct RequestContext {
    pub request_id: String,
    pub started_at: String,
    pub path: String,
}

#[derive(Clone, Default)]
pub struct ContextMiddleware;

pub fn context() -> ContextMiddleware {
    ContextMiddleware
}

impl<S, B> Transform<S, ServiceRequest> for ContextMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ContextMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ContextMiddlewareService {
            service: Rc::new(service),
        })
    }
}

pub struct ContextMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for ContextMiddlewareService<S>
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

        Box::pin(async move {
            let request_id = req
                .headers()
                .get("x-request-id")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("req_{}", Uuid::new_v4().simple()));

            let ctx = RequestContext {
                request_id: request_id.clone(),
                started_at: Utc::now().to_rfc3339(),
                path: req.path().to_string(),
            };

            req.extensions_mut().insert(ctx);

            let mut res = service.call(req).await?;
            let header_name = HeaderName::from_static("x-request-id");
            if let Ok(header_value) = HeaderValue::from_str(&request_id) {
                res.headers_mut().insert(header_name, header_value);
            }

            Ok(res)
        })
    }
}

pub fn read_request_context(req: &actix_web::HttpRequest) -> Option<RequestContext> {
    req.extensions().get::<RequestContext>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpRequest, HttpResponse, test, web};

    async fn handler(req: HttpRequest) -> HttpResponse {
        let ctx = read_request_context(&req);
        if ctx.is_some() {
            HttpResponse::Ok().finish()
        } else {
            HttpResponse::InternalServerError().finish()
        }
    }

    #[actix_web::test]
    async fn context_injects_request_id_and_extension() {
        let app = test::init_service(
            App::new()
                .wrap(context())
                .route("/x", web::get().to(handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/x").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), actix_web::http::StatusCode::OK);
        assert!(res.headers().contains_key("x-request-id"));
    }
}
