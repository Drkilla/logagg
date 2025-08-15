// Exports des modules (équivalent de l'autoload Symfony)
pub mod cli;
pub mod docker_client;
pub mod log_entry;

// Re-exports pour simplifier l'usage
pub use cli::{Cli, Commands};
pub use docker_client::{DockerService, ContainerInfo};
pub use log_entry::{LogEntry, LogLevel, LogSource};