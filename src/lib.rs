// Exports des modules (équivalent de l'autoload Symfony)
pub mod cli;
pub mod docker_client;
pub mod log_entry;
pub mod log_discovery;
pub mod tui;

// Re-exports pour simplifier l'usage
pub use cli::{Cli, Commands};
pub use docker_client::{DockerService, ContainerInfo};
pub use log_entry::{LogEntry, LogLevel, LogSource};
pub use log_discovery::{LogDiscoverer, LogFileSource, LogCategory};
pub use tui::run_dashboard;