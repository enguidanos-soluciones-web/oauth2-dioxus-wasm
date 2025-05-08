use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use super::storage;

const TOKEN_RESPONSE_KEY: &str = "oauth_token_response";
const TOKEN_RESPONSE_EXPIRATION_KEY: &str = "oauth_token_response_expiration";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IdToken {
    pub sub: String,
    pub nonce: String,
}

impl FromStr for IdToken {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(parts) = s.split('.').nth(1) else {
            return Err("cant extract jwt parts".to_owned());
        };

        let decoded_parts = URL_SAFE_NO_PAD.decode(parts.as_bytes()).map_err(|e| e.to_string())?;
        let serialized = String::from_utf8(decoded_parts).map_err(|e| e.to_string())?;
        serde_json::from_str::<Self>(&serialized).map_err(|e| e.to_string())
    }
}

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
