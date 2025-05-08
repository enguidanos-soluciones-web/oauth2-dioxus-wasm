use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dioxus::logger::tracing;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use url::Url;
use url::form_urlencoded;
use web_sys::UrlSearchParams;

use crate::oauth2::csrf;
use crate::oauth2::params::Params;
use crate::oauth2::pkce;
use crate::oauth2::storage;
use crate::oauth2::token;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AzureIdToken {
    pub sub: String,
    pub nonce: String,
}

impl FromStr for AzureIdToken {
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

#[derive(Debug, Clone)]
pub struct AuthorizationCodeFlowWithPKCE {
    pub is_authenticated: Arc<AtomicBool>,

    hybrid_flow: bool,
    persistence: storage::StorageType,
    security_client_id: &'static str,
    security_tenant_id: &'static str,
    security_audience_id: &'static str,
}

impl AuthorizationCodeFlowWithPKCE {
    pub fn new(security_client_id: &'static str, security_tenant_id: &'static str, security_audience_id: &'static str) -> Self {
        Self {
            hybrid_flow: false,
            persistence: storage::StorageType::LocalStorage,
            is_authenticated: Arc::new(AtomicBool::new(false)),
            security_client_id,
            security_tenant_id,
            security_audience_id,
        }
    }

    pub fn with_local_storage(&mut self) {
        self.persistence = storage::StorageType::LocalStorage;
    }

    pub fn with_session_storage(&mut self) {
        self.persistence = storage::StorageType::SessionStorage;
    }

    pub fn with_hybrid_flow(&mut self) {
        self.hybrid_flow = true;
    }

    fn build_authorize_endpoint(&self) -> anyhow::Result<String> {
        let Some(window) = web_sys::window() else {
            anyhow::bail!("window not available");
        };

        let Ok(redirect_uri) = window.location().origin() else {
            anyhow::bail!("location origin not available");
        };

        let csrf_nonce = csrf::Nonce::new();
        csrf_nonce.persist(self.persistence)?;

        let csrf_state = csrf::State::new();
        csrf_state.persist(self.persistence)?;

        let pkce_code_verifier = pkce::CodeVerifier::new();
        pkce_code_verifier.persist(self.persistence)?;
        let pkce_code_challenge = pkce::CodeChallenge::from(&pkce_code_verifier);

        let base_url = &format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
            tenant_id = self.security_tenant_id
        );

        // microsoft encoding is obsolete
        let response_type = { if self.hybrid_flow { "code%20id_token" } else { "code" } };
        let response_mode = { if self.hybrid_flow { "fragment" } else { "query" } };

        let scope = {
            if self.hybrid_flow {
                format!("openid%20{audience}", audience = self.security_audience_id)
            } else {
                self.security_audience_id.to_owned()
            }
        };

        let mut params = vec![
            (Params::ClientId.to_string(), self.security_client_id),
            (Params::RedirectUri.to_string(), redirect_uri.as_str()),
            (Params::ResponseMode.to_string(), response_mode),
            (Params::State.to_string(), csrf_state.as_str()),
            (Params::CodeChallenge.to_string(), pkce_code_challenge.as_str()),
            (Params::CodeChallengeMethod.to_string(), "S256"),
        ];

        if self.hybrid_flow {
            params.push((Params::Nonce.to_string(), csrf_nonce.as_str()));
        }

        let mut base_url = Url::parse(base_url)?;

        for (key, value) in params.iter() {
            base_url.query_pairs_mut().append_pair(key, value);
        }

        Ok(format!(
            "{base}{scope}{response_type}",
            base = base_url.as_str(),
            scope = format!("&{}={}", Params::Scope, scope),
            response_type = format!("&{}={}", Params::ResponseType, response_type)
        ))
    }

    async fn request_authorization_token(&self, code: &str, state: &str) -> anyhow::Result<token::TokenResponse> {
        let Some(window) = web_sys::window() else {
            anyhow::bail!("window not available");
        };

        let Ok(redirect_uri) = window.location().origin() else {
            anyhow::bail!("location origin not available");
        };

        let code_verifier = pkce::CodeVerifier::retrieve(self.persistence)?;

        let params_raw = &[
            (Params::ClientId.to_string(), self.security_client_id),
            (Params::Scope.to_string(), self.security_audience_id),
            (Params::Code.to_string(), code),
            (Params::RedirectUri.to_string(), redirect_uri.as_str()),
            (Params::GrantType.to_string(), "authorization_code"),
            (Params::State.to_string(), state),
            (Params::CodeVerifier.to_string(), code_verifier.as_str()),
        ];

        let mut params = HashMap::new();
        for (k, v) in params_raw {
            params.insert(k, v);
        }

        let client = reqwest::Client::new();

        let response = client
            .post(format!(
                "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                tenant_id = self.security_tenant_id
            ))
            .form(&params)
            .send()
            .await?
            .json::<token::TokenResponse>()
            .await?;

        Ok(response)
    }

    fn clear_auth_params_from_url() -> anyhow::Result<()> {
        if let Some(window) = web_sys::window() {
            let location = window.location();

            let path = location
                .pathname()
                .map_err(|err| anyhow!("failed to get pathname: {:?}", err))?;

            if let Some(history) = window.history().ok() {
                history
                    .replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path))
                    .map_err(|err| anyhow!("failed to replace state: {:?}", err))?;
            }
        }

        Ok(())
    }

    fn extract_auth_params_from_url(&self) -> anyhow::Result<(Option<String>, Option<String>, Option<String>)> {
        let Some(window) = web_sys::window() else {
            anyhow::bail!("window not available");
        };

        // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
        if self.hybrid_flow {
            let hash = window
                .location()
                .hash()
                .map_err(|_| anyhow::anyhow!("location hash not available"))?;

            if hash.is_empty() {
                return Ok((None, None, None));
            }

            let hash_params = &hash[1..];

            let structured_hash_params: HashMap<String, String> = form_urlencoded::parse(hash_params.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            return Ok((
                structured_hash_params.get("code").cloned(),
                structured_hash_params.get("id_token").cloned(),
                structured_hash_params.get("state").cloned(),
            ));
        } else {
            let Ok(search) = window.location().search() else {
                anyhow::bail!("location search not available");
            };

            let url_search_params = UrlSearchParams::new_with_str(&search).map_err(|err| anyhow!("{err:?}"))?;

            return Ok((url_search_params.get("code"), None, url_search_params.get("state")));
        }
    }

    fn clear_all(&self) -> anyhow::Result<()> {
        Self::clear_auth_params_from_url()?;
        csrf::State::unpersist(self.persistence)?;
        pkce::CodeVerifier::unpersist(self.persistence)?;

        if self.hybrid_flow {
            csrf::Nonce::unpersist(self.persistence)?;
        }

        Ok(())
    }

    pub async fn login_with_redirect(&self) -> anyhow::Result<()> {
        let Some(window) = web_sys::window() else {
            anyhow::bail!("window not available");
        };

        let (code, id_token, state) = self.extract_auth_params_from_url()?;

        let Some(code) = code else {
            let endpoint_url = self.build_authorize_endpoint()?;

            window
                .location()
                .set_href(endpoint_url.as_str())
                .map_err(|err| anyhow!("{err:?}"))?;

            tracing::debug!("{endpoint_url}");

            return Ok(());
        };

        let Some(state) = state else {
            self.clear_all()?;
            anyhow::bail!("param state not available");
        };

        if !csrf::State::exists_and_matches_raw(self.persistence, &state) {
            tracing::error!("invalid state");

            self.clear_all()?;

            window
                .location()
                .set_pathname("/forbidden")
                .map_err(|err| anyhow!("{err:?}"))?;

            return Ok(());
        }

        let mut future_id_token: Option<String> = None;

        if self.hybrid_flow {
            let Some(id_token) = id_token else {
                anyhow::bail!("param id_token not available");
            };

            let id_token_parts = AzureIdToken::from_str(&id_token).map_err(|err| anyhow!("{err:?}"))?;

            if !csrf::Nonce::exists_and_matches_raw(self.persistence, &id_token_parts.nonce) {
                self.clear_all()?;

                window
                    .location()
                    .set_pathname("/forbidden")
                    .map_err(|err| anyhow!("{err:?}"))?;

                return Ok(());
            }

            future_id_token = Some(id_token);
        }

        let mut token_response = self.request_authorization_token(&code, &state).await?;
        token_response.id_token = future_id_token;
        token_response.persist(self.persistence)?;

        self.clear_all()?;

        self.is_authenticated.store(true, Ordering::Release);

        Ok(())
    }

    pub async fn acquire_token_silent(&self) -> anyhow::Result<Option<token::TokenResponse>> {
        let Some(window) = web_sys::window() else {
            anyhow::bail!("window not available");
        };

        if let Some(token_result) = token::TokenResponse::retrieve(self.persistence)? {
            return Ok(Some(token_result));
        }

        if let Some(token_response) = token::TokenResponse::retrieve_unchecked(self.persistence)? {
            let Ok(redirect_uri) = window.location().origin() else {
                anyhow::bail!("location origin not available");
            };

            let client = reqwest::Client::new();

            let params_raw = &[
                (Params::ClientId.to_string(), self.security_client_id),
                (Params::Scope.to_string(), self.security_audience_id),
                (Params::RefreshToken.to_string(), &token_response.refresh_token),
                (Params::RedirectUri.to_string(), redirect_uri.as_str()),
                (Params::GrantType.to_string(), "refresh_token"),
            ];

            let mut params = HashMap::new();
            for (k, v) in params_raw {
                params.insert(k, v);
            }

            let response = client
                .post(format!(
                    "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    tenant_id = self.security_tenant_id
                ))
                .form(&params)
                .send()
                .await?;

            match response.error_for_status() {
                Ok(out) => {
                    let token_response = out.json::<token::TokenResponse>().await?;
                    tracing::debug!("token_response {token_response:?}");
                    token_response.persist(self.persistence)?;
                    return Ok(Some(token_response));
                }
                Err(err) => {
                    tracing::warn!("failed to refresh token: {}", err);
                    token_response.unpersist(self.persistence)?;
                    self.login_with_redirect().await?;
                    return Ok(None);
                }
            }
        }

        self.login_with_redirect().await?;

        Ok(None)
    }
}
