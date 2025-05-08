use dioxus::prelude::*;

#[component]
pub fn HomePage() -> Element {
    rsx! {
        div {
            class: "p-10 grid gap-5",

            span {
                class: "grid overflow-x-auto",
                "Hello world!"
            }
        }
    }
}
