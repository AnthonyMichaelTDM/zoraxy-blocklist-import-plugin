use axum::response::IntoResponse;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Zoraxy API error: {0}")]
    ZoraxyApiError(#[from] reqwest::Error),
    #[error("Import already in progress")]
    ImportInProgress,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match &self {
            Error::ZoraxyApiError(_) => (
                axum::http::StatusCode::BAD_GATEWAY,
                self.to_string().clone(),
            ),

            Error::ImportInProgress => (
                axum::http::StatusCode::CONFLICT,
                "Import already in progress".to_string(),
            ),
        };

        tracing::error!("Error occurred: {}", error_message);

        let body = axum::Json(serde_json::json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
