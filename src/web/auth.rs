#![allow(dead_code)]

use askama::Template;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{async_trait, debug_handler, Form, RequestPartsExt, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Days, SubsecRound, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::secret_box::SecretBox;
use crate::{Error, Result};

use super::AppState;

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/login", get(login_form))
        .route("/register", get(register_form))
        .route("/sessions", get(sessions))
        .route("/logout", get(logout))
        .with_state(state)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionToken {
    /// Session ID.
    #[serde(rename = "jti")]
    pub session: Uuid,

    /// Session expiry.
    #[serde(with = "ts_seconds", rename = "exp")]
    pub expiry: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct Session {
    /// Session ID.
    pub session_id: Uuid,

    /// Session expiry.
    pub expiry: DateTime<Utc>,

    /// User ID.
    pub user_id: Uuid,

    /// Username
    pub username: String,
}

impl SessionToken {
    fn has_expired(&self) -> bool {
        self.expiry < Utc::now()
    }

    fn from_token_string(token_string: String, secret_box: &SecretBox) -> Result<Self> {
        let token_bytes = URL_SAFE
            .decode(token_string)
            .map_err(|_| Error::InvalidSessionToken)?;
        let decrypted_bytes = secret_box.open(&token_bytes)?;

        let session: Self =
            serde_json::from_slice(&decrypted_bytes).map_err(|_| Error::InvalidSessionToken)?;

        if session.has_expired() {
            return Err(Error::ExpiredSessionToken);
        }

        Ok(session)
    }

    fn to_token_string(&self, secret_box: &SecretBox) -> String {
        let decrypted_bytes = serde_json::to_vec(&self).unwrap();

        let sealed_bytes = secret_box.seal(&decrypted_bytes);

        URL_SAFE.encode(sealed_bytes)
    }
}

#[derive(Debug)]
struct User {
    user_id: Uuid,
    username: String,
}

#[derive(Deserialize)]
struct RegisterPayload {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct UserRecord {
    user_id: String,
    username: String,
    hash: Vec<u8>,
}

async fn register(
    State(state): State<AppState>,
    Form(payload): Form<RegisterPayload>,
) -> Result<Response> {
    if payload.username.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            RegisterTemplate {
                error: Some(format!("{}", Error::UsernameTooShort)),
            },
        )
            .into_response());
    }

    if payload.password.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            RegisterTemplate {
                error: Some(format!("{}", Error::PasswordTooShort)),
            },
        )
            .into_response());
    }

    let maybe_user = sqlx::query!(
        r#"SELECT user_id FROM "user" WHERE LOWER(username) = LOWER($1)"#,
        payload.username
    )
    .fetch_optional(&state.db)
    .await?;

    if maybe_user.is_some() {
        // The user already exists.
        return Ok((
            StatusCode::BAD_REQUEST,
            RegisterTemplate {
                error: Some(format!("{}", Error::UsernameAlreadyExists)),
            },
        )
            .into_response());
    }

    let user = User {
        user_id: Uuid::new_v4(),
        username: payload.username.clone(),
    };

    let hash = state
        .hasher
        .hash(user.user_id.to_string(), payload.password)
        .await?;

    let mut tx = state.db.begin().await?;

    sqlx::query!(
        r#"
            INSERT INTO "user" (user_id, username)
            VALUES ($1, $2)
        "#,
        user.user_id,
        user.username
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        r#"
            INSERT INTO "password" (user_id, hash)
            VALUES ($1, $2)
        "#,
        user.user_id,
        hash
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Redirect::to("/login").into_response())
}

#[derive(Debug, Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

async fn login(
    State(state): State<AppState>,
    cookies: CookieJar,
    Form(payload): Form<LoginPayload>,
) -> Result<Response> {
    if payload.username.is_empty() || payload.password.is_empty() {
        return Ok((
            StatusCode::UNAUTHORIZED,
            LoginTemplate {
                error: Some(format!("{}", Error::InvalidCredentials)),
            },
        )
            .into_response());
    }

    let maybe_user = sqlx::query!(
        r#"
        SELECT u.user_id AS "user_id: uuid::Uuid", u.username AS username, p.hash AS password_hash
        FROM "user" u JOIN password p ON u.user_id = p.user_id
        WHERE LOWER(username) = LOWER($1)
        "#,
        payload.username
    )
    .fetch_optional(&state.db)
    .await?;

    let Some(user) = maybe_user else {
        return Ok((
            StatusCode::UNAUTHORIZED,
            LoginTemplate {
                error: Some(format!("{}", Error::NoSuchUser)),
            },
        )
            .into_response());
    };

    if !(state
        .hasher
        .verify(
            user.user_id.to_string(),
            payload.password,
            user.password_hash,
        )
        .await?)
    {
        return Ok((
            StatusCode::UNAUTHORIZED,
            LoginTemplate {
                error: Some(format!("{}", Error::InvalidCredentials)),
            },
        )
            .into_response());
    }

    let session = create_session(user.user_id, state.db).await.unwrap();
    let session_token = session.to_token_string(&state.token_box);

    Ok((
        cookies.add(Cookie::new("session", session_token)),
        Redirect::to("/sessions"),
    )
        .into_response())
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
}

async fn login_form(session: Option<Session>) -> Response {
    if session.is_some() {
        return Redirect::to("/sessions").into_response();
    }

    LoginTemplate { error: None }.into_response()
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    error: Option<String>,
}

async fn register_form(session: Option<Session>) -> Response {
    if session.is_some() {
        return Redirect::to("/sessions").into_response();
    }

    RegisterTemplate { error: None }.into_response()
}

async fn logout(
    State(state): State<AppState>,
    cookies: CookieJar,
    session: Session,
) -> Result<impl IntoResponse> {
    sqlx::query!(
        r#"
            DELETE FROM "session" WHERE session = $1
        "#,
        session.session_id
    )
    .execute(&state.db)
    .await?;

    Ok((
        cookies.remove(Cookie::from("session")),
        Redirect::to("/login"),
    ))
}

#[derive(Template)]
#[template(path = "sessions.html")]
struct SessionsTemplate {
    username: String,
    session_id: String,
    sessions: Vec<String>,
}

async fn sessions(State(state): State<AppState>, session: Session) -> Result<SessionsTemplate> {
    let sessions: Vec<String> = sqlx::query!(
        r#"
            SELECT session AS "session: uuid::Uuid" FROM "session"
            WHERE user_id = $1
        "#,
        session.user_id
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .filter_map(|record| {
        if let Some(session) = record.session {
            return Some(session.to_string());
        }

        None
    })
    .collect();

    Ok(SessionsTemplate {
        username: session.username,
        session_id: session.session_id.to_string(),
        sessions,
    })
}

async fn create_session(user_id: Uuid, db: SqlitePool) -> Result<SessionToken> {
    let token = SessionToken {
        session: Uuid::new_v4(),
        expiry: Utc::now()
            .checked_add_days(Days::new(5))
            .unwrap()
            .round_subsecs(0),
    };

    sqlx::query!(
        r#"
            INSERT INTO "session" (session, user_id)
            VALUES ($1, $2)
        "#,
        token.session,
        user_id
    )
    .execute(&db)
    .await?;

    Ok(token)
}

#[async_trait]
impl FromRequestParts<AppState> for Session {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self> {
        let cookies = parts
            .extract::<CookieJar>()
            .await
            .map_err(|_| Error::InvalidSessionToken)?;

        let Some(session_token) = cookies.get("session") else {
            return Err(Error::InvalidSessionToken);
        };

        let decrypted_token =
            SessionToken::from_token_string(session_token.value().to_string(), &state.token_box)?;

        let Some(user) = sqlx::query!(
            r#"
                SELECT s.user_id AS "user_id: uuid::Uuid", u.username FROM "session" s JOIN "user" u on s.user_id = u.user_id
                WHERE session = $1
            "#,
            decrypted_token.session
        )
        .fetch_optional(&state.db)
        .await?
        else {
            return Err(Error::InvalidSessionToken);
        };

        Ok(Session {
            session_id: decrypted_token.session,
            expiry: decrypted_token.expiry,
            user_id: user.user_id,
            username: user.username,
        })
    }
}

#[test]
fn test_token_codec() {
    let secret_box = SecretBox::new(&[2; 32]).unwrap();

    let token = SessionToken {
        session: Uuid::new_v4(),
        expiry: Utc::now()
            .checked_add_days(Days::new(1))
            .unwrap()
            .round_subsecs(0),
    };

    let token_string = token.to_token_string(&secret_box);
    let decrypted_token = SessionToken::from_token_string(token_string, &secret_box).unwrap();

    assert_eq!(token, decrypted_token);
}

#[test]
fn test_expired_token() {
    let secret_box = SecretBox::new(&[2; 32]).unwrap();

    let token = SessionToken {
        session: Uuid::new_v4(),
        expiry: Utc::now().checked_sub_days(Days::new(1)).unwrap(),
    };

    let token_string = token.to_token_string(&secret_box);

    assert_eq!(
        SessionToken::from_token_string(token_string, &secret_box),
        Err(Error::ExpiredSessionToken)
    );
}
