use rand::Rng;

use crate::oauth2::storage;

const CSRF_STATE_KEY: &str = "oauth_csrf_state";
const CSRF_NONCE_KEY: &str = "oauth_csrf_nonce";

// https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
pub struct State {
    pub value: String,
}

impl State {
    pub fn new() -> Self {
        let random: f64 = rand::rng().random();

        Self {
            value: format!("{random}"),
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

        if let Ok(Some(state)) = storage.get_item(CSRF_STATE_KEY) {
            return Ok(Self { value: state });
        }

        anyhow::bail!("no state available");
    }

    pub fn exists_and_matches_raw(storage_type: storage::StorageType, n: &str) -> bool {
        if let Ok(state) = Self::retrieve(storage_type) {
            return state.as_str() == n;
        }

        false
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

        let Ok(_) = storage.set_item(CSRF_STATE_KEY, &self.value) else {
            anyhow::bail!("failed to save state");
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

        let Ok(_) = storage.remove_item(CSRF_STATE_KEY) else {
            anyhow::bail!("failed to save state");
        };

        Ok(())
    }
}

pub struct Nonce {
    pub value: String,
}

impl Nonce {
    pub fn new() -> Self {
        let random: f64 = rand::rng().random();

        Self {
            value: format!("{random}"),
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

        if let Ok(Some(state)) = storage.get_item(CSRF_NONCE_KEY) {
            return Ok(Self { value: state });
        }

        anyhow::bail!("no nonce available");
    }

    pub fn exists_and_matches_raw(storage_type: storage::StorageType, n: &str) -> bool {
        if let Ok(state) = Self::retrieve(storage_type) {
            return state.as_str() == n;
        }

        false
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

        let Ok(_) = storage.set_item(CSRF_NONCE_KEY, &self.value) else {
            anyhow::bail!("failed to save state");
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

        let Ok(_) = storage.remove_item(CSRF_NONCE_KEY) else {
            anyhow::bail!("failed to save state");
        };

        Ok(())
    }
}
