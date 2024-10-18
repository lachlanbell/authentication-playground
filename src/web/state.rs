use std::sync::Arc;

use sqlx::SqlitePool;

use crate::{password::Hasher, secret_box::SecretBox};

#[derive(Clone)]
pub struct AppState {
    pub token_box: Arc<SecretBox<'static>>,
    pub hasher: Arc<Hasher>,
    pub db: SqlitePool,
}
