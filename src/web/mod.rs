use std::net::SocketAddr;

use axum::{routing::get, Json, Router};
use serde::Serialize;
pub use state::AppState;

mod state;

pub async fn serve(state: AppState<'static>) {
    let app = Router::new().route("/up", get(up)).with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

#[derive(Serialize)]
struct StatusResponse {
    up: bool,
}

async fn up() -> Json<StatusResponse> {
    Json(StatusResponse { up: true })
}
