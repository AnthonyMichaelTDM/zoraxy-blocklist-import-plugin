use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use axum::Json;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::Request;
use axum::routing::{get, post};
use axum::{Router, debug_handler};
use reqwest::StatusCode;
use tokio::sync::Mutex;
use tracing::instrument;
use zoraxy_rs::prelude::*;

use crate::errors::Error;

mod errors;
mod zoraxy_types;

static WWW: include_dir::Dir = include_dir::include_dir!("www");

fn introspect() -> IntroSpect {
    let metadata = PluginMetadata::new(PluginType::Utilities)
        .with_id("com.anthonyrubick.zoraxy-blocklist-manager")
        .with_name("Blocklist Import Plugin")
        .with_author("Anthony Rubick")
        .with_contact("")
        .with_description("A plugin for importing blocklists into Zoraxy's Access Rules.")
        .with_url("https://github.com/AnthonyMichaelTDM/zoraxy-blocklist-import-plugin")
        .with_version((1, 0, 0));
    IntroSpect::new(metadata)
        .with_ui_path("/")
        .add_permitted_api_endpoint(
            PermittedApiEndpoint::new("POST", "/plugin/api/blacklist/ip/add")
                .with_reason("Used to add IP addresses to the blocklist"),
        )
        .add_permitted_api_endpoint(
            PermittedApiEndpoint::new("GET", "/plugin/api/access/list")
                .with_reason("Used to list available access rulesets"),
        )
}

#[derive(Clone, Debug)]
struct AppState {
    pub api_key: String,
    pub zoraxy_port: u16,
    pub reqwest_client: reqwest::Client,
    // Only allow one import at a time, to avoid overwhelming the Zoraxy API.
    pub importing_lock: Arc<Mutex<()>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let runtime_cfg = serve_and_recv_spec(std::env::args().collect(), &introspect())?;

    init_tracing_subscriber(false);

    let api_key = runtime_cfg
        .api_key
        .clone()
        .ok_or(anyhow!("missing API Key in runtime configuration"))?;
    let zoraxy_port = runtime_cfg
        .zoraxy_port
        .ok_or(anyhow!("missing Zoraxy Port in runtime configuration"))?;
    tracing::info!(
        "API Call Example Plugin initialized with port: {}, zoraxy_port: {}",
        runtime_cfg.port,
        zoraxy_port
    );

    let state = AppState {
        api_key,
        zoraxy_port,
        reqwest_client: reqwest::Client::builder()
            .user_agent("ZoraxyBlocklistImportPlugin/1.0")
            .build()?,
        importing_lock: Arc::new(Mutex::new(())),
    };
    // let state = Arc::new(state);

    let ui_router = Arc::new(PluginUiRouter::new(&WWW, "/"));

    let app = Router::new()
        .merge(rest_api_routes())
        .route_service("/", ui_router.into_service())
        .fallback(get(not_found_handler));

    let addr: SocketAddr = format!("127.0.0.1:{}", runtime_cfg.port).parse()?;
    tracing::info!("API Call Example Plugin UI ready at http://{addr}");
    start_plugin(app, state, addr, Some("/ui")).await
}

#[debug_handler]
async fn not_found_handler(req: Request<Body>) -> (StatusCode, String) {
    tracing::warn!("404 Not Found: {}", req.uri());
    (StatusCode::NOT_FOUND, String::from("Not Found"))
}

fn rest_api_routes() -> Router<AppState> {
    Router::new()
        .route("/api/import", post(handle_import_post))
        .route("/api/list-access-rules", get(handle_list_access_rules))
        .route(
            "/api/list-blocklisted-ips",
            get(handle_list_blocklisted_ips),
        )
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct AccessRuleQuery {
    pub rule_id: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct IpsToBlacklist {
    pub ips: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct ImportForm {
    #[serde(rename = "access_rule_id")]
    pub access_rule_id: String,
    #[serde(rename = "blocklist")]
    // comma separated list of IPs
    pub blocklist: String,
}

#[debug_handler]
async fn handle_import_post(
    State(ctx): State<AppState>,
    // The form will contain access_rule_id and blocklist (comma separated IPs)
    Query(form): Query<ImportForm>,
) -> Result<String, Error> {
    let ctx = ctx.clone();
    // Parse the IPs from the blocklist textarea.
    let ips: Vec<String> = form
        .blocklist
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let client = ctx.reqwest_client.clone();
    let url = format!(
        "http://localhost:{}/plugin/api/blacklist/ip/add?id={}",
        ctx.zoraxy_port, form.access_rule_id
    );
    let api_key = ctx.api_key.clone();

    // write the response before moving things into the background task
    let response = format!(
        "Started import of {} IPs to Access Rule ID: {}, check logs for progress.",
        ips.len(),
        form.access_rule_id
    );
    tracing::info!("{response}");

    if let Err(_) = ctx.importing_lock.try_lock() {
        return Err(Error::ImportInProgress);
    }

    // spawn a task to import the IPs in the background
    tokio::spawn(async move {
        let import_lock = ctx.importing_lock.clone();
        // Ensure only one import at a time.
        // we want to fail instead of blocking here.
        let Ok(import_lock) = import_lock.try_lock() else {
            tracing::warn!("Import already in progress, rejecting new import request");
            return;
        };

        // for each IP in payload.ips, add it to the Access Rule with ID form.access_rule_id
        for (i, ip) in ips.iter().enumerate() {
            tracing::info!(
                "Importing IP {}/{} to Access Rule ID: {}",
                i + 1,
                ips.len(),
                form.access_rule_id
            );

            if let Err(e) = client
                .post(&url)
                .query(&[("ip", ip)])
                .bearer_auth(&api_key)
                .send()
                .await
            {
                tracing::warn!(
                    access_rule_id = %form.access_rule_id,
                    ip = %ip,
                    error = %e,
                    "Failed to import IP to Access Rule"
                );
                continue;
            }
        }
        drop(import_lock); // release the lock
    });

    Ok(response)
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ListAccessRulesResponse {
    pub access_rules: Vec<zoraxy_types::AccessRule>,
}

#[debug_handler]
async fn handle_list_access_rules(
    State(state): State<AppState>,
) -> Result<Json<Vec<zoraxy_types::AccessRule>>, Error> {
    let client = state.reqwest_client.clone();
    let url = format!(
        "http://localhost:{}/plugin/api/access/list",
        state.zoraxy_port
    );
    let api_key = state.api_key.clone();

    let response = client.get(&url).bearer_auth(&api_key).send().await?;
    let access_rules: Vec<zoraxy_types::AccessRule> = response.json().await?;

    Ok(Json(access_rules))
}

#[instrument]
#[debug_handler]
async fn handle_list_blocklisted_ips(
    State(state): State<AppState>,
    Query(query): Query<AccessRuleQuery>,
) -> Result<Json<Vec<String>>, Error> {
    let client = state.reqwest_client.clone();
    let url = format!(
        "http://localhost:{}/plugin/api/blacklist/list?id={}&type=ip",
        state.zoraxy_port, query.rule_id
    );
    let api_key = state.api_key.clone();

    let response = client.get(&url).bearer_auth(&api_key).send().await?;
    let blocklisted_ips: Vec<String> = response.json().await?;

    Ok(Json(blocklisted_ips))
}
