use anyhow::{anyhow, Result};
use bollard::{
    container::{ListContainersOptions, LogsOptions},
    Docker,
};
use tokio_stream::{Stream, StreamExt};
use std::collections::HashMap;
use serde_json::Value;

use crate::log_entry::{LogEntry, LogLevel, LogSource, ParsedLogData};

/// Service pour interagir avec Docker (équivalent d'un Service Symfony)
pub struct DockerService {
    client: Docker,
}

/// Info sur un container Docker
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
}

impl DockerService {
    /// Crée une nouvelle instance du service (équivalent du constructeur avec DI)
    pub fn new() -> Result<Self> {
        let client = Docker::connect_with_socket_defaults()
            .map_err(|e| anyhow!("Impossible de se connecter à Docker: {}", e))?;

        Ok(Self { client })
    }

    /// Liste tous les containers en cours d'exécution (équivalent d'une méthode de Repository)
    pub async fn list_containers(&self) -> Result<Vec<ContainerInfo>> {
        let mut filters = HashMap::new();
        filters.insert("status".to_string(), vec!["running".to_string()]);

        let options = ListContainersOptions {
            filters,
            ..Default::default()
        };

        let containers = self.client
            .list_containers(Some(options))
            .await
            .map_err(|e| anyhow!("Erreur lors de la liste des containers: {}", e))?;

        let container_infos = containers
            .into_iter()
            .map(|container| {
                let name = container.names
                    .and_then(|names| names.first().cloned())
                    .unwrap_or_else(|| "unknown".to_string())
                    .trim_start_matches('/')
                    .to_string();

                ContainerInfo {
                    id: container.id.unwrap_or_else(|| "unknown".to_string()),
                    name,
                    image: container.image.unwrap_or_else(|| "unknown".to_string()),
                    status: container.status.unwrap_or_else(|| "unknown".to_string()),
                }
            })
            .collect();

        Ok(container_infos)
    }

    /// Stream les logs d'un container (équivalent d'un générateur PHP)
    pub async fn stream_container_logs(
        &self,
        container_id: &str,
        service_name: String,
    ) -> Result<impl Stream<Item = LogEntry>> {
        let options = LogsOptions::<String> {
            follow: true,
            stdout: true,
            stderr: true,
            timestamps: true,
            ..Default::default()
        };

        let logs_stream = self.client
            .logs(container_id, Some(options))
            .map(move |log_result| {
                let service_name = service_name.clone();

                match log_result {
                    Ok(log_output) => {
                        let bytes = log_output.into_bytes();
                        let content = String::from_utf8_lossy(&bytes);

                        if !content.trim().is_empty() {
                            let (level, parsed_data) = Self::parse_log_line(&content);

                            let entry = if let Some(data) = parsed_data {
                                LogEntry::new_with_data(
                                    service_name,
                                    level,
                                    content.trim().to_string(),
                                    LogSource::DockerStdout,
                                    data,
                                )
                            } else {
                                LogEntry::new(
                                    service_name,
                                    level,
                                    content.trim().to_string(),
                                    LogSource::DockerStdout,
                                )
                            };

                            Some(entry)
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        Some(LogEntry::new(
                            service_name,
                            LogLevel::Error,
                            format!("Erreur lors de la lecture des logs: {}", e),
                            LogSource::DockerStderr,
                        ))
                    }
                }
            })
            .filter_map(|entry| entry);

        Ok(logs_stream)
    }

    /// Parse une ligne de log pour extraire le niveau et les données structurées
    fn parse_log_line(line: &str) -> (LogLevel, Option<ParsedLogData>) {
        // Les logs Docker ont souvent un timestamp au début: "2025-08-15T02:11:18.326970090Z {...}"
        // On cherche le premier '{' pour extraire le JSON
        if let Some(json_start) = line.find('{') {
            let json_part = &line[json_start..];
            if let Ok(json) = serde_json::from_str::<Value>(json_part) {
                return Self::parse_json_log(&json);
            }
        }

        // Tentative de parsing JSON direct (au cas où il n'y aurait pas de timestamp)
        if let Ok(json) = serde_json::from_str::<Value>(line) {
            return Self::parse_json_log(&json);
        }

        // Fallback vers parsing basique
        let line_upper = line.to_uppercase();

        let level = if line_upper.contains("ERROR") || line_upper.contains("FATAL") {
            LogLevel::Error
        } else if line_upper.contains("WARN") || line_upper.contains("WARNING") {
            LogLevel::Warn
        } else if line_upper.contains("INFO") || line_upper.contains("NOTICE") {
            LogLevel::Info
        } else if line_upper.contains("DEBUG") {
            LogLevel::Debug
        } else {
            LogLevel::Info
        };

        (level, None)
    }

    /// Parse spécialisé pour les logs JSON (Caddy)
    fn parse_json_log(json: &Value) -> (LogLevel, Option<ParsedLogData>) {
        // Cas spécial : logs d'accès HTTP Caddy
        if let Some(request) = json.get("request") {
            if let (Some(method), Some(uri), Some(status)) = (
                request.get("method").and_then(|m| m.as_str()),
                request.get("uri").and_then(|u| u.as_str()),
                json.get("status").and_then(|s| s.as_u64()),
            ) {
                let level = match status {
                    200..=299 => LogLevel::Info,
                    300..=399 => LogLevel::Info,
                    400..=499 => LogLevel::Warn,
                    500..=599 => LogLevel::Error,
                    _ => LogLevel::Info,
                };

                let parsed_data = ParsedLogData::HttpRequest {
                    method: method.to_string(),
                    uri: uri.to_string(),
                    status: status as u16,
                    duration_ms: json.get("duration").and_then(|d| d.as_f64()).unwrap_or(0.0),
                    size_bytes: json.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
                    remote_ip: request.get("remote_ip")
                        .and_then(|ip| ip.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                };

                return (level, Some(parsed_data));
            }
        }

        // Cas général : logs système JSON
        let level = if let Some(level_str) = json.get("level").and_then(|l| l.as_str()) {
            match level_str.to_lowercase().as_str() {
                "error" | "fatal" => LogLevel::Error,
                "warn" | "warning" => LogLevel::Warn,
                "info" => LogLevel::Info,
                "debug" => LogLevel::Debug,
                _ => LogLevel::Info,
            }
        } else {
            LogLevel::Info
        };

        // Extrait logger et message pour les logs génériques
        let logger = json.get("logger")
            .and_then(|l| l.as_str())
            .unwrap_or("system")
            .to_string();

        let message = json.get("msg")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown message")
            .to_string();

        let parsed_data = ParsedLogData::GenericJson { logger, message };

        (level, Some(parsed_data))
    }
}