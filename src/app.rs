use dioxus::prelude::*;

use crate::router::Route;

#[component]
pub fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: asset!("/assets/favicon.ico") }
        document::Link { rel: "stylesheet", href: asset!("/assets/main.css") }


        Router::<Route> {}
    }
}
