# Wasm APP with Azure OAUTH2.0 Authorization Code Flow with PKCE and Hybrid Flow

### MacOS

```
brew install llvm
echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
llvm-config --version
```

### Serving App

```bash
# install js dependencies
pnpm i

# run tailwindcss
npx @tailwindcss/cli -i ./styles/main.css -o ./assets/main.css --minimize

# run wasm app
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' dx serve --port 5173
```

### Example of usage

```rs
use crate::{components::navbar::NavbarComponent, oauth2, router::Route};
use dioxus::{logger::tracing, prelude::*};
use std::sync::{Arc, atomic::Ordering};

#[component]
pub fn SecurityLayout() -> Element {
    let oauth2_client = use_context_provider(|| {
        let client = oauth2::azure::AuthorizationCodeFlowWithPKCE::default()
            .with_client_id("00000000-0000-0000-0000-000000000000")
            .with_scope("api://00000000-0000-0000-0000-000000000000/access")
            .with_oidc_url("https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration")
            .with_hybrid_flow()
            .with_session_storage();

        Arc::new(client)
    });

    let mut is_authenticated = use_signal(|| false);

    use_effect(move || {
        let oauth2_client = Arc::clone(&oauth2_client);

        spawn(async move {
            if let Err(error) = oauth2_client.login_with_redirect().await {
                tracing::error!("{error:?}");
                return;
            }

            is_authenticated.set(oauth2_client.is_authenticated.load(Ordering::Acquire));
        });
    });

    rsx! {
        if is_authenticated() {
            NavbarComponent {}

            Outlet::<Route> {}
        } else {
            p {
                "signing in..."
            }
        }
    }
}
```
