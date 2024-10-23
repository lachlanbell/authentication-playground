use askama::Template;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
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
        match self {
            Self::ExpiredSessionToken | Self::InvalidSessionToken => {
                Redirect::to("/login").into_response()
            }
            _ => {
                if cfg!(feature = "web_errors") {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ErrorTemplate {
                            error: "Internal Server Error".to_string(),
                            description: Some(format!("{}", self)),
                        },
                    )
                        .into_response()
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ErrorTemplate {
                            error: "Internal Server Error".to_string(),
                            description: None,
                        },
                    )
                        .into_response()
                }
            }
        }
    }
}
