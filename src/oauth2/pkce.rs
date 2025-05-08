use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::storage;

const PKCE_CODE_VERIFIER_KEY: &str = "oauth_pkce_code_verifier";

// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
pub struct CodeVerifier {
    pub value: String,
}

impl CodeVerifier {
    pub fn new() -> Self {
        let mut buffer = [0u8; 64];
        rand::rng().fill_bytes(&mut buffer);

        Self {
            value: URL_SAFE_NO_PAD.encode(buffer),
        }
    }

    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub fn retrieve(storage_type: storage::StorageType) -> anyhow::Result<Self> {
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

        if let Ok(Some(state)) = storage.get_item(PKCE_CODE_VERIFIER_KEY) {
            return Ok(Self { value: state });
        }

        anyhow::bail!("no pkce code verifier available");
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

        let Ok(_) = storage.set_item(PKCE_CODE_VERIFIER_KEY, &self.value) else {
            anyhow::bail!("failed to save pkce code verifier");
        };

        Ok(())
    }

    pub fn unpersist(storage_type: storage::StorageType) -> anyhow::Result<()> {
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

        let Ok(_) = storage.remove_item(PKCE_CODE_VERIFIER_KEY) else {
            anyhow::bail!("failed to remove pkce code verifier");
        };

        Ok(())
    }
}

// https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
pub struct CodeChallenge {
    pub value: String,
}

impl From<&CodeVerifier> for CodeChallenge {
    fn from(value: &CodeVerifier) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(value.as_str().as_bytes());
        let hash = hasher.finalize();

        Self {
            value: URL_SAFE_NO_PAD.encode(hash),
        }
    }
}

impl CodeChallenge {
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }
}
