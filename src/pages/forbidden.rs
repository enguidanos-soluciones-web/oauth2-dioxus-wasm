use dioxus::prelude::*;

#[component]
pub fn ForbiddenPage() -> Element {
    rsx! {
        div {
            class: "p-10 grid gap-5",
            p {
               "No tiene acceso. Hable con el administrador."
            }
        }
    }
}
