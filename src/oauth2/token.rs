use dioxus::logger::tracing;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::storage;

const TOKEN_RESPONSE_KEY: &str = "oauth_token_response";
const TOKEN_RESPONSE_EXPIRATION_KEY: &str = "oauth_token_response_expiration";

pub trait TokenVerifier<T>
where
    T: DeserializeOwned,
{
    async fn verify(
        client_id: &'static str,
        issuers_urls: &'static [&'static str],
        keys_url: &'static str,
        s: &str,
    ) -> anyhow::Result<T> {
        let header = jsonwebtoken::decode_header(s)?;

        let Some(kid) = header.kid else {
            anyhow::bail!("kid not found");
        };

        let Some(jwkset) = Self::fetch_jkwset(keys_url).await else {
            anyhow::bail!("jkwset not fetched");
        };

        let Some(jwk) = jwkset.find(&kid) else {
            anyhow::bail!("kid not found");
        };

        return match jwk.algorithm {
            jsonwebtoken::jwk::AlgorithmParameters::RSA(ref rsa) => {
                let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
                validation.set_issuer(issuers_urls);
                validation.set_audience(&[client_id]);

                let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?;

                let jsonwebtoken::TokenData { claims, .. } = jsonwebtoken::decode::<T>(s, &decoding_key, &validation)?;

                Ok(claims)
            }
            _ => anyhow::bail!("invalid algorithm on token"),
        };
    }

    // TODO: implement cache on storage for 12h
    async fn fetch_jkwset(keys_url: &'static str) -> Option<jsonwebtoken::jwk::JwkSet> {
        let client = reqwest::Client::new();

        let Ok(response) = client.get(keys_url).send().await else {
            tracing::error!("impossible to request to jwk_keys_url");
            return None;
        };

        let Ok(jwkset) = response.json::<jsonwebtoken::jwk::JwkSet>().await else {
            tracing::error!("impossible to extract jwk_set");
            return None;
        };

        return Some(jwkset);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IdToken {
    pub sub: String,
    pub nonce: String,
}

impl TokenVerifier<IdToken> for IdToken {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub ext_expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
    pub token_type: String,
    pub id_token: Option<String>,
}

impl TokenResponse {
    pub fn retrieve(storage_type: storage::StorageType) -> anyhow::Result<Option<Self>> {
        let storage = match storage_type {
            storage::StorageType::LocalStorage => {
                let Some(storage) = storage::local_storage() else {
                    anyhow::bail!("no local storage available");
                };
                storage
            }
            storage::StorageType::SessionStorage => {
                let Some(storage) = storage::session_storage() else {
                    anyhow::bail!("no session storage available");
                };
                storage
            }
        };

        if let Ok(Some(token_response)) = storage.get_item(TOKEN_RESPONSE_KEY) {
            if let Ok(Some(token_response_expiration)) = storage.get_item(TOKEN_RESPONSE_EXPIRATION_KEY) {
                if let Ok(expires_at) = token_response_expiration.parse::<i64>() {
                    if chrono::Utc::now().timestamp() < expires_at {
                        return Ok(Some(serde_json::from_str(&token_response)?));
                    }
                }
            }
        }

        Ok(None)
    }

    pub fn retrieve_unchecked(storage_type: storage::StorageType) -> anyhow::Result<Option<Self>> {
        let storage = match storage_type {
            storage::StorageType::LocalStorage => {
                let Some(storage) = storage::local_storage() else {
                    anyhow::bail!("no local storage available");
                };
                storage
            }
            storage::StorageType::SessionStorage => {
                let Some(storage) = storage::session_storage() else {
                    anyhow::bail!("no session storage available");
                };
                storage
            }
        };

        if let Ok(Some(token_response)) = storage.get_item(TOKEN_RESPONSE_KEY) {
            return Ok(Some(serde_json::from_str(&token_response)?));
        }

        Ok(None)
    }

    pub fn persist(&self, storage_type: storage::StorageType) -> anyhow::Result<()> {
        let storage = match storage_type {
            storage::StorageType::LocalStorage => {
                let Some(storage) = storage::local_storage() else {
                    anyhow::bail!("no local storage available");
                };
                storage
            }
            storage::StorageType::SessionStorage => {
                let Some(storage) = storage::session_storage() else {
                    anyhow::bail!("no session storage available");
                };
                storage
            }
        };

        let Ok(_) = storage.set_item(TOKEN_RESPONSE_KEY, &serde_json::to_string(&self)?) else {
            anyhow::bail!("failed to save token response");
        };

        let delta = 5; /* delay time for computing */
        let expires_at = chrono::Utc::now().timestamp() + self.expires_in - delta;

        let Ok(_) = storage.set_item(TOKEN_RESPONSE_EXPIRATION_KEY, &expires_at.to_string()) else {
            anyhow::bail!("failed to save token expiration");
        };

        Ok(())
    }

    pub fn unpersist(&self, storage_type: storage::StorageType) -> anyhow::Result<()> {
        let storage = match storage_type {
            storage::StorageType::LocalStorage => {
                let Some(storage) = storage::local_storage() else {
                    anyhow::bail!("no local storage available");
                };
                storage
            }
            storage::StorageType::SessionStorage => {
                let Some(storage) = storage::session_storage() else {
                    anyhow::bail!("no session storage available");
                };
                storage
            }
        };

        let Ok(_) = storage.remove_item(TOKEN_RESPONSE_KEY) else {
            anyhow::bail!("failed to remove token response");
        };
        let Ok(_) = storage.remove_item(TOKEN_RESPONSE_EXPIRATION_KEY) else {
            anyhow::bail!("failed to remove token expiration");
        };

        Ok(())
    }
}
