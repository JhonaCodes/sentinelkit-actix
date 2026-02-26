use actix_web::http::{StatusCode, header::ETAG};
use actix_web::{HttpResponse, ResponseError};
use chrono::Utc;
use serde::ser::Serializer;
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    Unauthorized,
    InvalidToken,
    Forbidden,
    NotFound,
    ValidationError,
    InvalidFormat,
    OutOfRange,
    Conflict,
    RateLimited,
    InternalError,
    Custom(String),
}

impl ErrorCode {
    pub fn custom(code: impl Into<String>) -> Self {
        Self::Custom(code.into())
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidToken => "INVALID_TOKEN",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::ValidationError => "VALIDATION_ERROR",
            Self::InvalidFormat => "INVALID_FORMAT",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Conflict => "CONFLICT",
            Self::RateLimited => "RATE_LIMITED",
            Self::InternalError => "INTERNAL_ERROR",
            Self::Custom(value) => value.as_str(),
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum I18nKey {
    ErrorsUnauthorized,
    ErrorsInvalidToken,
    ErrorsForbidden,
    ErrorsNotFound,
    ErrorsValidationError,
    ErrorsInvalidFormat,
    ErrorsOutOfRange,
    ErrorsConflict,
    ErrorsRateLimited,
    ErrorsInternalError,
    Custom(String),
}

impl I18nKey {
    pub fn custom(key: impl Into<String>) -> Self {
        Self::Custom(key.into())
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::ErrorsUnauthorized => "errors.unauthorized",
            Self::ErrorsInvalidToken => "errors.invalid_token",
            Self::ErrorsForbidden => "errors.forbidden",
            Self::ErrorsNotFound => "errors.not_found",
            Self::ErrorsValidationError => "errors.validation_error",
            Self::ErrorsInvalidFormat => "errors.invalid_format",
            Self::ErrorsOutOfRange => "errors.out_of_range",
            Self::ErrorsConflict => "errors.conflict",
            Self::ErrorsRateLimited => "errors.rate_limited",
            Self::ErrorsInternalError => "errors.internal_error",
            Self::Custom(value) => value.as_str(),
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Self::ErrorsUnauthorized => "errors.unauthorized",
            Self::ErrorsInvalidToken => "errors.invalid_token",
            Self::ErrorsForbidden => "errors.forbidden",
            Self::ErrorsNotFound => "errors.not_found",
            Self::ErrorsValidationError => "errors.validation_error",
            Self::ErrorsInvalidFormat => "errors.invalid_format",
            Self::ErrorsOutOfRange => "errors.out_of_range",
            Self::ErrorsConflict => "errors.conflict",
            Self::ErrorsRateLimited => "errors.rate_limited",
            Self::ErrorsInternalError => "errors.internal_error",
            Self::Custom(value) => value.as_str(),
        }
    }
}

impl Serialize for I18nKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.value())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiMeta {
    pub status: u16,
    pub timestamp: String,
    pub request_id: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationMeta>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaginationMeta {
    pub page: u32,
    pub page_size: u32,
    pub total_items: u64,
    pub total_pages: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiSuccess<T: Serialize> {
    pub data: T,
    pub meta: ApiMeta,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i18n_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorBody {
    pub code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i18n_key: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<ErrorDetail>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorEnvelope {
    pub error: ApiErrorBody,
    pub meta: ApiMeta,
}

#[derive(Debug, Clone)]
pub struct AppError {
    pub code: ErrorCode,
    pub i18n_key: Option<I18nKey>,
    pub message: Option<String>,
    pub details: Vec<ErrorDetail>,
    pub request_id: Option<String>,
    pub path: Option<String>,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.code)
    }
}

impl AppError {
    pub fn unauthorized() -> Self {
        Self::new(ErrorCode::Unauthorized)
    }
    pub fn forbidden() -> Self {
        Self::new(ErrorCode::Forbidden)
    }
    pub fn not_found() -> Self {
        Self::new(ErrorCode::NotFound)
    }
    pub fn validation() -> Self {
        Self::new(ErrorCode::ValidationError)
    }
    pub fn conflict() -> Self {
        Self::new(ErrorCode::Conflict)
    }
    pub fn rate_limited() -> Self {
        Self::new(ErrorCode::RateLimited)
    }
    pub fn internal() -> Self {
        Self::new(ErrorCode::InternalError)
    }

    pub fn custom(code: impl Into<String>) -> Self {
        Self::new(ErrorCode::custom(code))
    }

    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            i18n_key: None,
            message: None,
            details: Vec::new(),
            request_id: None,
            path: None,
        }
    }

    pub fn with_i18n(mut self, key: I18nKey) -> Self {
        self.i18n_key = Some(key);
        self
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn with_detail(mut self, detail: ErrorDetail) -> Self {
        self.details.push(detail);
        self
    }

    pub fn with_context(
        mut self,
        request_id: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        self.request_id = Some(request_id.into());
        self.path = Some(path.into());
        self
    }

    fn default_message(&self) -> &'static str {
        match &self.code {
            ErrorCode::Unauthorized => "Authentication is required.",
            ErrorCode::InvalidToken => "The authentication token is invalid.",
            ErrorCode::Forbidden => "You do not have permission to access this resource.",
            ErrorCode::NotFound => "The requested resource was not found.",
            ErrorCode::ValidationError => "Some fields are invalid.",
            ErrorCode::InvalidFormat => "The input format is invalid.",
            ErrorCode::OutOfRange => "The input value is out of allowed range.",
            ErrorCode::Conflict => "The operation conflicts with current state.",
            ErrorCode::RateLimited => "Too many requests. Please retry later.",
            ErrorCode::InternalError => "An unexpected error occurred. Please try again later.",
            ErrorCode::Custom(_) => "An unexpected error occurred. Please try again later.",
        }
    }

    fn status_code(&self) -> StatusCode {
        match &self.code {
            ErrorCode::Unauthorized | ErrorCode::InvalidToken => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::ValidationError | ErrorCode::InvalidFormat | ErrorCode::OutOfRange => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Custom(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        self.status_code()
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let meta = ApiMeta {
            status: status.as_u16(),
            timestamp: Utc::now().to_rfc3339(),
            request_id: self
                .request_id
                .clone()
                .unwrap_or_else(|| "req_unknown".to_string()),
            path: self.path.clone().unwrap_or_else(|| "unknown".to_string()),
            etag: None,
            pagination: None,
        };

        let body = ApiErrorEnvelope {
            error: ApiErrorBody {
                code: self.code.clone(),
                i18n_key: self.i18n_key.as_ref().map(|k| k.value().to_string()),
                message: self
                    .message
                    .clone()
                    .unwrap_or_else(|| self.default_message().to_string()),
                details: self.details.clone(),
            },
            meta,
        };

        HttpResponse::build(status).json(body)
    }
}

#[derive(Debug, Clone)]
pub struct ResponseContext<'a> {
    pub request_id: &'a str,
    pub path: &'a str,
}

fn meta(status: u16, ctx: ResponseContext<'_>, etag: Option<String>) -> ApiMeta {
    ApiMeta {
        status,
        timestamp: Utc::now().to_rfc3339(),
        request_id: ctx.request_id.to_string(),
        path: ctx.path.to_string(),
        etag,
        pagination: None,
    }
}

pub fn ok<T: Serialize>(ctx: ResponseContext<'_>, data: T) -> HttpResponse {
    HttpResponse::Ok().json(ApiSuccess {
        data,
        meta: meta(200, ctx, None),
    })
}

pub fn created<T: Serialize>(ctx: ResponseContext<'_>, data: T) -> HttpResponse {
    HttpResponse::Created().json(ApiSuccess {
        data,
        meta: meta(201, ctx, None),
    })
}

pub fn no_content(ctx: ResponseContext<'_>) -> HttpResponse {
    HttpResponse::NoContent()
        .insert_header(("x-request-id", ctx.request_id))
        .insert_header(("x-response-path", ctx.path))
        .finish()
}

pub fn not_modified(etag: &str) -> HttpResponse {
    HttpResponse::NotModified().insert_header((ETAG, etag)).finish()
}

pub fn detail(field: impl Into<String>, code: ErrorCode, i18n_key: Option<I18nKey>) -> ErrorDetail {
    ErrorDetail {
        field: Some(field.into()),
        code,
        i18n_key: i18n_key.as_ref().map(|k| k.value().to_string()),
        message: None,
    }
}

pub struct Response;

impl Response {
    pub fn ok_with<T: Serialize>(data: T, ctx: ResponseContext<'_>) -> HttpResponse {
        ok(ctx, data)
    }

    pub fn created_with<T: Serialize>(data: T, ctx: ResponseContext<'_>) -> HttpResponse {
        created(ctx, data)
    }

    pub fn no_content_with(ctx: ResponseContext<'_>) -> HttpResponse {
        no_content(ctx)
    }

    pub fn not_modified_with(etag: &str) -> HttpResponse {
        not_modified(etag)
    }

    pub fn ok_paginated_with<T: Serialize>(
        data: T,
        page: u32,
        page_size: u32,
        total_items: u64,
        ctx: ResponseContext<'_>,
    ) -> HttpResponse {
        let total_pages = if page_size == 0 {
            0
        } else {
            ((total_items + page_size as u64 - 1) / page_size as u64) as u32
        };

        HttpResponse::Ok().json(ApiSuccess {
            data,
            meta: ApiMeta {
                status: 200,
                timestamp: Utc::now().to_rfc3339(),
                request_id: ctx.request_id.to_string(),
                path: ctx.path.to_string(),
                etag: None,
                pagination: Some(PaginationMeta {
                    page,
                    page_size,
                    total_items,
                    total_pages,
                }),
            },
        })
    }
}

pub trait ResultResponseExt<T>
where
    T: Serialize,
{
    fn ok_with(self, ctx: ResponseContext<'_>) -> Result<HttpResponse, AppError>;
    fn created_with(self, ctx: ResponseContext<'_>) -> Result<HttpResponse, AppError>;
}

impl<T> ResultResponseExt<T> for Result<T, AppError>
where
    T: Serialize,
{
    fn ok_with(self, ctx: ResponseContext<'_>) -> Result<HttpResponse, AppError> {
        self.map(|data| ok(ctx, data))
    }

    fn created_with(self, ctx: ResponseContext<'_>) -> Result<HttpResponse, AppError> {
        self.map(|data| created(ctx, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::MessageBody;
    use actix_web::http::StatusCode;

    #[test]
    fn app_error_validation_maps_to_422() {
        let err = AppError::validation().with_i18n(I18nKey::ErrorsValidationError);
        assert_eq!(err.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn ok_contains_meta_status_200() {
        let res = ok(
            ResponseContext {
                request_id: "req_1",
                path: "/v1/test",
            },
            serde_json::json!({ "x": 1 }),
        );
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn no_content_returns_204() {
        let res = no_content(ResponseContext {
            request_id: "req_1",
            path: "/v1/test",
        });
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn result_extension_ok_with_works() {
        let payload = serde_json::json!({ "status": "ok" });
        let res = Ok::<_, AppError>(payload).ok_with(ResponseContext {
            request_id: "req_2",
            path: "/v1/health",
        });
        assert!(res.is_ok());
        assert_eq!(res.expect("response").status(), StatusCode::OK);
    }

    #[test]
    fn response_ok_paginated_contains_pagination_meta() {
        let res = Response::ok_paginated_with(
            vec![serde_json::json!({ "id": "h1" })],
            2,
            10,
            35,
            ResponseContext {
                request_id: "req_3",
                path: "/v1/hotels",
            },
        );
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().try_into_bytes().expect("bytes");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["meta"]["pagination"]["page"], 2);
        assert_eq!(json["meta"]["pagination"]["total_pages"], 4);
    }

    #[test]
    fn custom_error_and_i18n_keys_are_supported() {
        let err = AppError::custom("HOTEL_NOT_AVAILABLE")
            .with_i18n(I18nKey::custom("errors.hotel.not_available"))
            .with_detail(detail(
                "hotel_id",
                ErrorCode::custom("HOTEL_NOT_AVAILABLE"),
                Some(I18nKey::custom("errors.hotel.not_available")),
            ));
        let res = err.error_response();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
