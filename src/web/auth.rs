#![allow(dead_code)]

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{debug_handler, Form, Router};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Days, SubsecRound, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secret_box::SecretBox;
use crate::{Error, Result};

use super::AppState;

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register))
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

#[debug_handler]
async fn register(
    State(state): State<AppState>,
    Form(payload): Form<RegisterPayload>,
) -> Result<StatusCode> {
    let maybe_user = sqlx::query!(
        r#"SELECT user_id FROM "user" WHERE username = $1"#,
        payload.username
    )
    .fetch_optional(&state.db)
    .await?;

    if maybe_user.is_some() {
        // The user already exists.
        return Err(Error::UsernameAlreadyExists);
    }

    let user = User { user_id: Uuid::new_v4(), username: payload.username.clone() };
    let hash = state.hasher.hash(user.user_id.to_string(), payload.password).await?;

    let mut tx = state.db.begin().await?;

    let uuid_string = user.user_id.to_string();

    sqlx::query!(
        r#"
            INSERT INTO "user" (user_id, username)
            VALUES ($1, $2)
        "#,
        uuid_string,
        user.username
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        r#"
            INSERT INTO "password" (user_id, hash)
            VALUES ($1, $2)
        "#,
        uuid_string,
        hash
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
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
