use dioxus::prelude::*;

use crate::{
    layouts::security::SecurityLayout,
    pages::{forbidden::ForbiddenPage, home::HomePage},
};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
pub enum Route {
    #[layout(SecurityLayout)]
        #[route("/", HomePage)]
        Home {},
    #[end_layout]

    #[route("/forbidden", ForbiddenPage)]
    Forbidden {},
}
