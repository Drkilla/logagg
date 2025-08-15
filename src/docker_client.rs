use anyhow::{anyhow, Result};
use bollard::{
    container::{ListContainersOptions, LogsOptions},
    Docker,
};
use tokio_stream::{Stream, StreamExt};
use std::collections::HashMap;
use serde_json::Value;
use regex::Regex;
use chrono;

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

    pub fn get_client(&self) -> Docker {
        self.client.clone()
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

    /// Récupère les derniers logs d'un container pour le TUI
    pub async fn get_recent_logs(
        &self,
        container_id: &str,
        service_name: String,
        tail_lines: u32,
    ) -> Result<Vec<LogEntry>> {
        let options = LogsOptions::<String> {
            follow: false,
            stdout: true,
            stderr: true,
            timestamps: true,
            tail: format!("{}", tail_lines),
            ..Default::default()
        };

        let mut logs = Vec::new();
        let mut log_stream = self.client.logs(container_id, Some(options));

        while let Some(log_result) = log_stream.next().await {
            match log_result {
                Ok(log_output) => {
                    let bytes = log_output.into_bytes();
                    let content = String::from_utf8_lossy(&bytes);

                    if !content.trim().is_empty() {
                        let (level, parsed_data, extracted_timestamp) = Self::parse_log_line(&content);
                        
                        // Garde le timestamp Docker mais nettoie le contenu
                        let message = content.trim().to_string();

                        let entry = if let Some(timestamp) = extracted_timestamp {
                            // Utilise le timestamp extrait
                            LogEntry::new_with_timestamp(
                                timestamp,
                                service_name.clone(),
                                level,
                                message,
                                LogSource::DockerStdout,
                                parsed_data,
                            )
                        } else {
                            // Fallback vers timestamp actuel
                            if let Some(data) = parsed_data {
                                LogEntry::new_with_data(
                                    service_name.clone(),
                                    level,
                                    message,
                                    LogSource::DockerStdout,
                                    data,
                                )
                            } else {
                                LogEntry::new(
                                    service_name.clone(),
                                    level,
                                    message,
                                    LogSource::DockerStdout,
                                )
                            }
                        };

                        logs.push(entry);
                    }
                }
                Err(e) => {
                    logs.push(LogEntry::new(
                        service_name.clone(),
                        LogLevel::Error,
                        format!("Erreur lors de la lecture des logs: {}", e),
                        LogSource::DockerStderr,
                    ));
                }
            }
        }

        // Trie les logs par timestamp pour garantir l'ordre chronologique
        logs.sort_by_key(|log| log.timestamp);

        Ok(logs)
    }

    /// Récupère les nouveaux logs depuis un timestamp donné (pour TUI temps réel)
    pub async fn get_new_logs_since(
        &self,
        container_id: &str,
        service_name: String,
        since_unix_timestamp: i64,
    ) -> Result<Vec<LogEntry>> {
        let options = LogsOptions::<String> {
            follow: false,
            stdout: true,
            stderr: true,
            timestamps: true,
            since: since_unix_timestamp,
            ..Default::default()
        };

        let mut logs = Vec::new();
        let mut log_stream = self.client.logs(container_id, Some(options));

        while let Some(log_result) = log_stream.next().await {
            match log_result {
                Ok(log_output) => {
                    let bytes = log_output.into_bytes();
                    let content = String::from_utf8_lossy(&bytes);

                    if !content.trim().is_empty() {
                        let (level, parsed_data, extracted_timestamp) = Self::parse_log_line(&content);
                        
                        // Garde le timestamp Docker mais nettoie le contenu
                        let message = content.trim().to_string();

                        let entry = if let Some(timestamp) = extracted_timestamp {
                            // Utilise le timestamp extrait
                            LogEntry::new_with_timestamp(
                                timestamp,
                                service_name.clone(),
                                level,
                                message,
                                LogSource::DockerStdout,
                                parsed_data,
                            )
                        } else {
                            // Fallback vers timestamp actuel
                            if let Some(data) = parsed_data {
                                LogEntry::new_with_data(
                                    service_name.clone(),
                                    level,
                                    message,
                                    LogSource::DockerStdout,
                                    data,
                                )
                            } else {
                                LogEntry::new(
                                    service_name.clone(),
                                    level,
                                    message,
                                    LogSource::DockerStdout,
                                )
                            }
                        };

                        logs.push(entry);
                    }
                }
                Err(e) => {
                    logs.push(LogEntry::new(
                        service_name.clone(),
                        LogLevel::Error,
                        format!("Erreur lors de la lecture des logs: {}", e),
                        LogSource::DockerStderr,
                    ));
                }
            }
        }

        // Trie les logs par timestamp pour garantir l'ordre chronologique
        logs.sort_by_key(|log| log.timestamp);

        Ok(logs)
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
                            let (level, parsed_data, extracted_timestamp) = Self::parse_log_line(&content);
                            
                            // Garde le timestamp Docker mais nettoie le contenu
                            let message = content.trim().to_string();

                            let entry = if let Some(timestamp) = extracted_timestamp {
                                // Utilise le timestamp extrait
                                LogEntry::new_with_timestamp(
                                    timestamp,
                                    service_name,
                                    level,
                                    message,
                                    LogSource::DockerStdout,
                                    parsed_data,
                                )
                            } else {
                                // Fallback vers timestamp actuel
                                if let Some(data) = parsed_data {
                                    LogEntry::new_with_data(
                                        service_name,
                                        level,
                                        message,
                                        LogSource::DockerStdout,
                                        data,
                                    )
                                } else {
                                    LogEntry::new(
                                        service_name,
                                        level,
                                        message,
                                        LogSource::DockerStdout,
                                    )
                                }
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

    /// Parse une ligne de log pour extraire le niveau, les données structurées et le timestamp
    fn parse_log_line(line: &str) -> (LogLevel, Option<ParsedLogData>, Option<chrono::DateTime<chrono::Utc>>) {
        // 1. Extrait le timestamp Docker du début si présent
        let docker_timestamp = Self::extract_docker_timestamp(line);
        let cleaned_line = Self::remove_docker_timestamp(line);
        
        // 2. Cas spécial : JSON Symfony (logs en format JSON)
        if let Ok(json) = serde_json::from_str::<Value>(&cleaned_line) {
            let (level, parsed_data) = Self::parse_json_log(&json);
            
            // Essaie d'extraire le timestamp du JSON (datetime field)
            let json_timestamp = json.get("datetime")
                .and_then(|dt| dt.as_str())
                .and_then(|dt_str| chrono::DateTime::parse_from_rfc3339(dt_str).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));
            
            return (level, parsed_data, json_timestamp.or(docker_timestamp));
        }

        // 3. Chercher du JSON dans la ligne après nettoyage
        if let Some(json_start) = cleaned_line.find('{') {
            let json_part = &cleaned_line[json_start..];
            if let Ok(json) = serde_json::from_str::<Value>(json_part) {
                let (level, parsed_data) = Self::parse_json_log(&json);
                
                // Essaie d'extraire le timestamp du JSON
                let json_timestamp = json.get("datetime")
                    .and_then(|dt| dt.as_str())
                    .and_then(|dt_str| chrono::DateTime::parse_from_rfc3339(dt_str).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc));
                
                return (level, parsed_data, json_timestamp.or(docker_timestamp));
            }
        }

        // 4. Essayer de parser le format Symfony texte: [TIMESTAMP] CHANNEL.LEVEL: MESSAGE {JSON} []
        if let Some((level, parsed_data)) = Self::parse_symfony_log(&cleaned_line) {
            return (level, parsed_data, docker_timestamp);
        }

        // 5. Fallback vers parsing basique avec line nettoyée
        let line_upper = cleaned_line.to_uppercase();

        let level = if line_upper.contains("ERROR") || line_upper.contains("FATAL") || line_upper.contains("EXCEPTION") {
            LogLevel::Error
        } else if line_upper.contains("WARN") || line_upper.contains("WARNING") {
            LogLevel::Warn
        } else if line_upper.contains("INFO") || line_upper.contains("NOTICE") {
            // Filtre les messages de debug Symfony trop verbeux
            if cleaned_line.contains("[debug] Notified event") {
                LogLevel::Debug // Déclasse en debug
            } else {
                LogLevel::Info
            }
        } else if line_upper.contains("DEBUG") {
            LogLevel::Debug
        } else {
            LogLevel::Info
        };

        // Retourne avec le timestamp Docker ou l'heure actuelle
        (level, None, docker_timestamp)
    }

    /// Extrait le timestamp Docker du début de la ligne si présent
    fn extract_docker_timestamp(line: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        let re = Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)").unwrap();
        re.captures(line)
            .and_then(|caps| caps.get(1))
            .and_then(|m| chrono::DateTime::parse_from_rfc3339(m.as_str()).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }

    /// Supprime le timestamp Docker au début de la ligne si présent
    fn remove_docker_timestamp(line: &str) -> String {
        // Regex pour matcher le timestamp Docker: 2025-08-15T14:37:00.829302466Z
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s*").unwrap();
        re.replace(line, "").to_string()
    }

    /// Parse spécialisé pour les logs Symfony: [TIMESTAMP] CHANNEL.LEVEL: MESSAGE {CONTEXT} []
    fn parse_symfony_log(line: &str) -> Option<(LogLevel, Option<ParsedLogData>)> {
        // Regex pour matcher: [2025-08-15T15:39:57.641943+02:00] app.WARNING: HTTP client error {...} []
        let re = Regex::new(r"^\[([^\]]+)\] (\w+)\.(\w+): (.+?) (\{.*?\}) \[\]$").ok()?;

        if let Some(captures) = re.captures(line) {
            let timestamp = captures.get(1)?.as_str();
            let channel = captures.get(2)?.as_str();
            let level_name = captures.get(3)?.as_str();
            let message = captures.get(4)?.as_str();
            let context_str = captures.get(5)?.as_str();

            // Parse le niveau
            let level = match level_name.to_uppercase().as_str() {
                "ERROR" | "CRITICAL" | "ALERT" | "EMERGENCY" => LogLevel::Error,
                "WARNING" => LogLevel::Warn,
                "INFO" | "NOTICE" => LogLevel::Info,
                "DEBUG" => LogLevel::Debug,
                _ => LogLevel::Info,
            };

            // Parse le contexte JSON
            let context = serde_json::from_str::<Value>(context_str).unwrap_or(Value::Null);

            let parsed_data = ParsedLogData::SymfonyLog {
                channel: channel.to_string(),
                level_name: level_name.to_string(),
                message: message.to_string(),
                context,
                timestamp: timestamp.to_string(),
            };

            return Some((level, Some(parsed_data)));
        }

        None
    }

    /// Parse spécialisé pour les logs JSON (Caddy)
    /// Parse spécialisé pour les logs JSON (Caddy + Symfony)
    fn parse_json_log(json: &Value) -> (LogLevel, Option<ParsedLogData>) {
        // 1. CAS SPÉCIAL : logs Symfony JSON
        if let Some(channel) = json.get("channel") {
            if let Some(level_name) = json.get("level_name") {
                // C'est un log Symfony en format JSON !
                let level = match level_name.as_str().unwrap_or("").to_uppercase().as_str() {
                    "ERROR" | "CRITICAL" | "ALERT" | "EMERGENCY" => LogLevel::Error,
                    "WARNING" => LogLevel::Warn,
                    "INFO" | "NOTICE" => LogLevel::Info,
                    "DEBUG" => LogLevel::Debug,
                    _ => LogLevel::Info,
                };

                let message = json.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown message")
                    .to_string();

                let context = json.get("context").cloned().unwrap_or(Value::Null);

                let timestamp = json.get("datetime")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();

                let parsed_data = ParsedLogData::SymfonyLog {
                    channel: channel.as_str().unwrap_or("unknown").to_string(),
                    level_name: level_name.as_str().unwrap_or("").to_string(),
                    message,
                    context,
                    timestamp,
                };

                return (level, Some(parsed_data));
            }
        }

        // 2. CAS SPÉCIAL : logs d'accès HTTP Caddy
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

        // 3. CAS GÉNÉRAL : logs système JSON
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