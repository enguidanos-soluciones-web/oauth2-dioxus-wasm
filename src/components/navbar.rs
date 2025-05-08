use std::sync::Arc;

use dioxus::{logger::tracing, prelude::*};

use crate::oauth2;

#[component]
pub fn NavbarComponent() -> Element {
    let oauth2_client = use_context::<Arc<oauth2::azure::AuthorizationCodeFlowWithPKCE>>();

    let print_token = move |_| {
        let oauth2_client = Arc::clone(&oauth2_client);

        spawn(async move {
            if let Ok(Some(token)) = oauth2_client.acquire_token_silent().await {
                tracing::info!("{token:?}");
            }
        });
    };

    rsx! {
        button {
            onclick: print_token,
            class: "bg-green-600 text-white p-4 rounded",

            "Print Token"
        }
    }
}
