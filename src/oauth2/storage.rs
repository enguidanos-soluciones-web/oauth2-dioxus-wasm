#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum StorageType {
    LocalStorage,
    SessionStorage,
}

impl Default for StorageType {
    fn default() -> Self {
        Self::LocalStorage
    }
}

pub fn local_storage() -> Option<web_sys::Storage> {
    if let Some(window) = web_sys::window() {
        if let Ok(storage) = window.local_storage() {
            return storage;
        }
    }
    None
}

pub fn session_storage() -> Option<web_sys::Storage> {
    if let Some(window) = web_sys::window() {
        if let Ok(storage) = window.session_storage() {
            return storage;
        }
    }
    None
}
