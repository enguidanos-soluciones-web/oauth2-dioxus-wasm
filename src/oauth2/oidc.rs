use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub token_endpoint: String,
    pub authorization_endpoint: String,
}

impl Configuration {
    // TODO implement cache each 12h
    pub async fn from_remote(oidc_url: &'static str) -> anyhow::Result<Self> {
        let client = reqwest::Client::new();
        let conf = client.get(oidc_url).send().await?.json::<Self>().await?;
        Ok(conf)
    }
}
