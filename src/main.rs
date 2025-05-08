mod app;
mod components;
mod layouts;
mod oauth2;
mod pages;
mod router;

fn main() {
    dioxus::launch(app::App);
}
