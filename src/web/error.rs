use askama::Template;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::Error;

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    error: String,
    description: Option<String>,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if cfg!(not(debug_assertions)) {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorTemplate {
                    error: "Internal Server Error".to_string(),
                    description: None,
                },
            )
                .into_response()
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorTemplate {
                    error: "Internal Server Error".to_string(),
                    description: Some(format!("{}", self)),
                },
            )
                .into_response()
        }
    }
}
