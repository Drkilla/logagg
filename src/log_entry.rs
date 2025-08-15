use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Représente une entrée de log (équivalent d'une Entity Symfony)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub service: String,      // "web", "db", "redis"
    pub level: LogLevel,      // ERROR, WARN, INFO, DEBUG
    pub message: String,
    pub source: LogSource,    // Docker stdout/stderr ou fichier app
    pub parsed_data: Option<ParsedLogData>, // Données structurées extraites
}

/// Données structurées extraites des logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParsedLogData {
    HttpRequest {
        method: String,
        uri: String,
        status: u16,
        duration_ms: f64,
        size_bytes: u64,
        remote_ip: String,
    },
    GenericJson {
        logger: String,
        message: String,
    },
    SymfonyLog {
        channel: String,
        level_name: String,
        message: String,
        context: serde_json::Value,
        timestamp: String,
    },
}

/// Niveau de log (comme un enum Symfony)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Trace => write!(f, "TRACE"),
        }
    }
}

/// Source du log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogSource {
    DockerStdout,
    DockerStderr,
    ApplicationFile { path: String },
}

impl fmt::Display for LogSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogSource::DockerStdout => write!(f, "docker"),
            LogSource::DockerStderr => write!(f, "docker-err"),
            LogSource::ApplicationFile { path } => write!(f, "file:{}", path),
        }
    }
}

impl LogEntry {
    /// Crée une nouvelle entrée de log
    pub fn new(
        service: String,
        level: LogLevel,
        message: String,
        source: LogSource,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            service,
            level,
            message,
            source,
            parsed_data: None,
        }
    }

    /// Crée une entrée avec données structurées
    pub fn new_with_data(
        service: String,
        level: LogLevel,
        message: String,
        source: LogSource,
        parsed_data: ParsedLogData,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            service,
            level,
            message,
            source,
            parsed_data: Some(parsed_data),
        }
    }

    /// Crée une entrée avec timestamp personnalisé
    pub fn new_with_timestamp(
        timestamp: DateTime<Utc>,
        service: String,
        level: LogLevel,
        message: String,
        source: LogSource,
        parsed_data: Option<ParsedLogData>,
    ) -> Self {
        Self {
            timestamp,
            service,
            level,
            message,
            source,
            parsed_data,
        }
    }

    /// Format pour affichage console (équivalent d'un __toString())
    pub fn format_colored(&self) -> String {
        use colored::*;

        let timestamp = self.timestamp.format("%H:%M:%S%.3f");
        let service = format!("[{}]", self.service).blue().bold();
        let source = format!("[{}]", self.source).cyan();

        let level_colored = match self.level {
            LogLevel::Error => self.level.to_string().red().bold(),
            LogLevel::Warn => self.level.to_string().yellow().bold(),
            LogLevel::Info => self.level.to_string().green(),
            LogLevel::Debug => self.level.to_string().white(),
            LogLevel::Trace => self.level.to_string().bright_black(),
        };

        // Si on a des données structurées, on les formate joliment
        let formatted_message = if let Some(data) = &self.parsed_data {
            self.format_parsed_data(data)
        } else {
            self.message.clone()
        };

        format!(
            "{} {} {} {} {}",
            timestamp.to_string().bright_black(),
            service,
            source,
            level_colored,
            formatted_message
        )
    }

    /// Formate les données parsées de manière lisible
    fn format_parsed_data(&self, data: &ParsedLogData) -> String {
        use colored::*;

        match data {
            ParsedLogData::HttpRequest { method, uri, status, duration_ms, size_bytes, remote_ip } => {
                let method_colored = match method.as_str() {
                    "GET" => method.green(),
                    "POST" => method.blue(),
                    "PUT" => method.yellow(),
                    "DELETE" => method.red(),
                    _ => method.white(),
                };

                let status_colored = match *status {
                    200..=299 => status.to_string().green(),
                    300..=399 => status.to_string().cyan(),
                    400..=499 => status.to_string().yellow(),
                    500..=599 => status.to_string().red(),
                    _ => status.to_string().white(),
                };

                let size_human = if *size_bytes > 1024 * 1024 {
                    format!("{:.1}MB", *size_bytes as f64 / (1024.0 * 1024.0))
                } else if *size_bytes > 1024 {
                    format!("{:.1}KB", *size_bytes as f64 / 1024.0)
                } else {
                    format!("{}B", size_bytes)
                };

                format!(
                    "{} {} → {} ({:.0}ms, {}) from {}",
                    method_colored.bold(),
                    uri.white(),
                    status_colored.bold(),
                    duration_ms * 1000.0, // Convertit en ms
                    size_human.bright_black(),
                    remote_ip.bright_black()
                )
            },
            ParsedLogData::GenericJson { logger, message } => {
                format!("[{}] {}", logger.cyan(), message)
            },
            ParsedLogData::SymfonyLog { channel, level_name: _, message, context, timestamp: _ } => {
                let channel_colored = match channel.as_str() {
                    "app" => channel.blue(),
                    "request" => channel.green(),
                    "security" => channel.red(),
                    "doctrine" => channel.purple(),
                    _ => channel.white(),
                };

                // Extrait des infos importantes du contexte
                let mut context_parts = Vec::new();

                // Pour les erreurs HTTP
                if let Some(method) = context.get("method") {
                    if let Some(url) = context.get("url") {
                        context_parts.push(format!("{} {}",
                                                   method.as_str().unwrap_or("?").yellow().bold(),
                                                   url.as_str().unwrap_or("?").white()
                        ));
                    }
                }

                // Status code
                if let Some(status) = context.get("status_code") {
                    if let Some(status_num) = status.as_u64() {
                        let status_colored = match status_num {
                            200..=299 => status_num.to_string().green(),
                            300..=399 => status_num.to_string().cyan(),
                            400..=499 => status_num.to_string().yellow(),
                            500..=599 => status_num.to_string().red(),
                            _ => status_num.to_string().white(),
                        };
                        context_parts.push(format!("→ {}", status_colored));
                    }
                }

                // IP address
                if let Some(ip) = context.get("ip") {
                    context_parts.push(format!("from {}", ip.as_str().unwrap_or("?").bright_black()));
                }

                // Exception class (shortened)
                if let Some(exception_class) = context.get("exception_class") {
                    let short_exception = exception_class.as_str()
                        .unwrap_or("Exception")
                        .split('\\')
                        .last()
                        .unwrap_or("Exception");
                    context_parts.push(short_exception.red().to_string());
                }

                // File and line (pour les erreurs)
                if let Some(file) = context.get("file") {
                    if let Some(line) = context.get("line") {
                        let short_file = file.as_str()
                            .unwrap_or("")
                            .split('/')
                            .last()
                            .unwrap_or("unknown");
                        context_parts.push(format!("at {}:{}",
                                                   short_file.bright_black(),
                                                   line.as_u64().unwrap_or(0).to_string().bright_black()
                        ));
                    }
                }

                let context_info = if !context_parts.is_empty() {
                    format!(" {}", context_parts.join(" "))
                } else {
                    String::new()
                };

                format!(
                    "[{}] {}{}",
                    channel_colored.bold(),
                    message.trim(),
                    context_info
                )
            }
        }
    }
}