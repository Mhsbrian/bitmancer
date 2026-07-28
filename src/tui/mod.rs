// src/tui/mod.rs

pub mod app;
pub mod image_render;
pub mod map;
pub mod theme;
pub mod viewer;
pub mod event;
// `tui::tui` holds the terminal setup and teardown, distinct from `tui::ui`
// which draws. Renaming either would cost more churn than the repetition does.
#[allow(clippy::module_inception)]
pub mod tui;
pub mod ui;
pub mod widgets;
