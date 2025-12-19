#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AccessRule {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Desc")]
    pub desc: String,
    #[serde(rename = "BlacklistEnabled")]
    pub blacklist_enabled: bool,
    #[serde(rename = "WhitelistEnabled")]
    pub whitelist_enabled: bool,
}
