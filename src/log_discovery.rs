use anyhow::{anyhow, Result};
use bollard::{
    exec::{CreateExecOptions, StartExecResults},
    Docker,
};
use tokio_stream::StreamExt;
use regex::Regex;
use chrono::Utc;
use crate::log_entry::ParsedLogData;

/// Représente un fichier de log découvert dans un container
#[derive(Debug, Clone)]
pub struct LogFileSource {
    pub container_id: String,
    pub container_name: String,
    pub file_path: String,           // "/var/log/nginx/access.log"
    pub file_name: String,           // "access.log"
    pub category: LogCategory,       // Auto-détecté
    pub is_active: bool,             // Modifié récemment ?
    pub size_bytes: u64,            // Taille du fichier
    pub sample_content: String,      // Quelques lignes pour analyse
}

/// Catégories de logs auto-détectées
#[derive(Debug, Clone, PartialEq)]
pub enum LogCategory {
    WebServer,      // Nginx, Apache, Caddy
    Application,    // Symfony, Laravel, etc.
    Database,       // PostgreSQL, MySQL, Redis
    System,         // Système, Docker, etc.
    Unknown,        // Fallback
}

/// Découvreur de fichiers de logs dans les containers
pub struct LogDiscoverer {
    docker: Docker,
}

impl LogDiscoverer {
    pub fn new(docker: Docker) -> Self {
        Self { docker }
    }

    /// Lit les logs depuis les fichiers découverts dans un container
    pub async fn read_log_files(&self, container_id: &str, container_name: &str, tail_lines: u32) -> Result<Vec<crate::LogEntry>> {
        // 1. Découvre les fichiers de logs
        let log_sources = self.discover_log_files(container_id, container_name).await?;
        
        // Si aucun fichier trouvé, retourne une erreur pour fallback vers Docker
        if log_sources.is_empty() {
            return Err(anyhow!("Aucun fichier de logs trouvé dans le container"));
        }
        
        let mut all_logs = Vec::new();
        
        // 2. Lit chaque fichier de log
        for source in log_sources {
            match self.read_log_file_content(container_id, container_name, &source.file_path, tail_lines).await {
                Ok(mut logs) => {
                    // Ajoute la source du fichier à chaque log
                    for log in &mut logs {
                        log.source = crate::LogSource::ApplicationFile { 
                            path: source.file_path.clone() 
                        };
                    }
                    all_logs.extend(logs);
                }
                Err(_e) => {
                    // eprintln!("Erreur lecture fichier {}: {}", source.file_path, e);
                }
            }
        }
        
        // Si pas de logs lus, retourne une erreur pour fallback
        if all_logs.is_empty() {
            return Err(anyhow!("Impossible de lire le contenu des fichiers de logs"));
        }
        
        // 3. Trie par timestamp
        all_logs.sort_by_key(|log| log.timestamp);
        
        Ok(all_logs)
    }

    /// Lit le contenu d'un fichier de log spécifique
    async fn read_log_file_content(&self, container_id: &str, container_name: &str, file_path: &str, tail_lines: u32) -> Result<Vec<crate::LogEntry>> {
        let tail_lines_str = tail_lines.to_string();
        let exec_config = CreateExecOptions {
            cmd: Some(vec!["tail", "-n", &tail_lines_str, file_path]),
            attach_stdout: Some(true),
            attach_stderr: Some(false),
            ..Default::default()
        };

        let exec = self.docker.create_exec(container_id, exec_config).await?;

        let mut output_string = String::new();
        let stream = self.docker.start_exec(&exec.id, None).await?;

        match stream {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(chunk) = output.next().await {
                    if let Ok(log_output) = chunk {
                        let bytes = log_output.into_bytes();
                        output_string.push_str(&String::from_utf8_lossy(&bytes));
                    }
                }
            }
            StartExecResults::Detached => {
                return Err(anyhow!("Exec détaché"));
            }
        }

        // Parse chaque ligne en LogEntry
        let mut logs = Vec::new();
        for line in output_string.lines() {
            if !line.trim().is_empty() {
                // Utilise notre parser existant mais pour les fichiers
                let (level, parsed_data, extracted_timestamp) = Self::parse_file_log_line(line);
                
                let timestamp = extracted_timestamp.unwrap_or_else(|| chrono::Utc::now());
                
                let log_entry = crate::LogEntry::new_with_timestamp(
                    timestamp,
                    container_name.to_string(),
                    level,
                    line.to_string(),
                    crate::LogSource::ApplicationFile { path: file_path.to_string() },
                    parsed_data,
                );
                
                logs.push(log_entry);
            }
        }

        Ok(logs)
    }

    /// Parse une ligne de fichier de log (différent des logs Docker)
    fn parse_file_log_line(line: &str) -> (crate::LogLevel, Option<ParsedLogData>, Option<chrono::DateTime<chrono::Utc>>) {
        // 1. Essaie de parser les logs Symfony en format classique
        if let Some((level, data, timestamp)) = Self::parse_symfony_file_log(line) {
            return (level, data, timestamp);
        }

        // 2. Essaie le JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let (level, data) = Self::parse_json_log(&json);
            let timestamp = json.get("datetime")
                .and_then(|dt| dt.as_str())
                .and_then(|dt_str| chrono::DateTime::parse_from_rfc3339(dt_str).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));
            return (level, data, timestamp);
        }

        // 3. Fallback parsing basique
        let level = if line.to_uppercase().contains("ERROR") {
            crate::LogLevel::Error
        } else if line.to_uppercase().contains("WARN") {
            crate::LogLevel::Warn  
        } else if line.to_uppercase().contains("INFO") {
            crate::LogLevel::Info
        } else if line.to_uppercase().contains("DEBUG") {
            crate::LogLevel::Debug
        } else {
            crate::LogLevel::Info
        };

        (level, None, None)
    }

    /// Parse les logs Symfony en format fichier : [2025-08-15T20:23:22+02:00] app.WARNING: message
    fn parse_symfony_file_log(line: &str) -> Option<(crate::LogLevel, Option<ParsedLogData>, Option<chrono::DateTime<chrono::Utc>>)> {
        // Regex pour [timestamp] channel.level: message
        let re = regex::Regex::new(r"^\[([^\]]+)\] (\w+)\.(\w+): (.+)$").ok()?;
        
        if let Some(captures) = re.captures(line) {
            let timestamp_str = captures.get(1)?.as_str();
            let channel = captures.get(2)?.as_str();
            let level_name = captures.get(3)?.as_str();
            let message = captures.get(4)?.as_str();

            // Parse le timestamp
            let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
                .or_else(|_| chrono::DateTime::parse_from_str(timestamp_str, "%Y-%m-%d %H:%M:%S"))
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .ok();

            // Parse le niveau
            let level = match level_name.to_uppercase().as_str() {
                "ERROR" | "CRITICAL" | "ALERT" | "EMERGENCY" => crate::LogLevel::Error,
                "WARNING" => crate::LogLevel::Warn,
                "INFO" | "NOTICE" => crate::LogLevel::Info,
                "DEBUG" => crate::LogLevel::Debug,
                _ => crate::LogLevel::Info,
            };

            let parsed_data = ParsedLogData::SymfonyLog {
                channel: channel.to_string(),
                level_name: level_name.to_string(),
                message: message.to_string(),
                context: serde_json::Value::Null,
                timestamp: timestamp_str.to_string(),
            };

            return Some((level, Some(parsed_data), timestamp));
        }

        None
    }

    /// Utilise le parser JSON existant (statique pour éviter les dépendances circulaires)
    fn parse_json_log(json: &serde_json::Value) -> (crate::LogLevel, Option<ParsedLogData>) {
        // Réutilise la logique de parsing JSON
        if let Some(level_str) = json.get("level").and_then(|l| l.as_str()) {
            let level = match level_str.to_lowercase().as_str() {
                "error" | "fatal" => crate::LogLevel::Error,
                "warn" | "warning" => crate::LogLevel::Warn,
                "info" => crate::LogLevel::Info,
                "debug" => crate::LogLevel::Debug,
                _ => crate::LogLevel::Info,
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
        } else {
            (crate::LogLevel::Info, None)
        }
    }

    /// Découvre tous les fichiers de logs dans un container
    pub async fn discover_log_files(&self, container_id: &str, container_name: &str) -> Result<Vec<LogFileSource>> {
        // println!("🔍 Recherche des fichiers .log dans {}", container_name);

        // 1. Cherche tous les fichiers .log
        let log_file_paths = self.find_log_files_in_container(container_id).await?;

        // 2. Analyse chaque fichier trouvé
        let mut log_sources = Vec::new();
        for file_path in log_file_paths {
            if let Ok(source) = self.analyze_log_file(container_id, container_name, &file_path).await {
                log_sources.push(source);
            }
        }

        // 3. Filtre les fichiers actifs et pas trop gros
        let active_sources: Vec<LogFileSource> = log_sources
            .into_iter()
            .filter(|source| source.is_active && source.size_bytes < 100_000_000)  // < 100MB
            .collect();

        // println!("📄 {} fichiers de logs actifs trouvés", active_sources.len());
        Ok(active_sources)
    }

    /// Découverte hybride : exploration intelligente + patterns connus
    async fn find_log_files_in_container(&self, container_id: &str) -> Result<Vec<String>> {
        // println!("   🎯 Découverte hybride intelligente...");
        
        let mut all_log_files = Vec::new();

        // Stratégie 1: Recherche dans les dossiers évidents avec wildcard
        let search_patterns = [
            ("*.log", "Fichiers .log classiques"),
            ("*access*", "Logs d'accès"),
            ("*error*", "Logs d'erreurs"), 
            ("*.out", "Fichiers de sortie"),
        ];

        for (pattern, _description) in &search_patterns {
            // println!("      🔍 {}: {}", description, pattern);
            
            // Cherche dans tout le système
            if let Ok(files) = self.execute_simple_command(
                container_id, 
                vec!["find", "/", "-name", pattern, "-type", "f", "-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/dev/*"]
            ).await {
                // println!("          → {} fichiers trouvés", files.len());
                all_log_files.extend(files);
            }
        }

        // Stratégie 2: Exploration des dossiers typiques
        let typical_dirs = ["/var/log", "/var/www", "/app", "/tmp"];
        for dir in &typical_dirs {
            // println!("      📁 Exploration de {}", dir);
            
            if let Ok(files) = self.execute_simple_command(
                container_id,
                vec!["find", dir, "-type", "f", "-size", "+10c"]
            ).await {
                // Filtre les fichiers qui ressemblent à des logs
                let log_files: Vec<String> = files
                    .into_iter()
                    .filter(|path| self.path_looks_like_log(path))
                    .collect();
                
                // println!("          → {} fichiers pertinents trouvés", log_files.len());
                all_log_files.extend(log_files);
            }
        }

        // Dédoublonnage
        all_log_files.sort();
        all_log_files.dedup();

        // println!("   ✅ {} fichiers uniques détectés", all_log_files.len());
        Ok(all_log_files)
    }

    /// Détermine rapidement si un path ressemble à un log (filtrage intelligent)
    fn path_looks_like_log(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        
        // Exclusions strictes (faux positifs courants)
        let exclusions = [
            ".git/", ".composer/", "node_modules/", ".cache/", ".idea/",
            "/var/cache/", "/tmp/tmp", ".json", ".php", ".css", ".js",
            ".png", ".jpg", ".ico", ".svg", ".zip", ".tar", ".gz",
            ".meta", ".xml", ".yaml", ".yml", ".twig", ".sql"
        ];
        
        // Si le path contient une exclusion, on ignore
        if exclusions.iter().any(|&exclusion| path_lower.contains(exclusion)) {
            return false;
        }
        
        // Extensions typiques des vrais logs
        if path_lower.ends_with(".log") || path_lower.ends_with(".out") || path_lower.ends_with(".err") {
            return true;
        }
        
        // Mots-clés dans le nom du fichier (pas dans tout le path)
        let filename = path_lower.split('/').last().unwrap_or("");
        let log_keywords = ["access", "error", "debug", "trace", "audit", "syslog", "messages"];
        log_keywords.iter().any(|&keyword| filename.contains(keyword))
    }

    /// Découvre tous les fichiers texte dans le container (hors exclusions système)
    async fn discover_all_text_files(&self, container_id: &str) -> Result<Vec<String>> {
        // Test avec la méthode qui marche
        let files = self.execute_simple_command(container_id, vec!["find", "/var", "-type", "f"]).await?;
        // println!("        Debug: {} fichiers bruts trouvés", files.len());
        
        // Affiche quelques exemples pour debug
        for (_i, _file) in files.iter().take(5).enumerate() {
            // println!("        Debug exemple {}: {}", i+1, file);
        }
        
        // Filtrage supplémentaire côté Rust pour plus de contrôle
        let text_files: Vec<String> = files
            .into_iter()
            .filter(|path| self.could_be_text_file(path))
            .collect();

        Ok(text_files)
    }

    /// Détermine si un fichier pourrait être un log selon son path
    fn is_likely_log_file(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        
        // Patterns positifs (très probablement des logs)
        let positive_indicators = [
            "log", "access", "error", "debug", "trace", 
            "audit", "journal", "syslog", "messages",
            ".out", ".err", "stdout", "stderr"
        ];
        
        // Si le path contient un indicateur positif
        if positive_indicators.iter().any(|&indicator| path_lower.contains(indicator)) {
            return true;
        }

        // Dossiers typiques de logs
        let log_directories = [
            "/var/log/", "/var/logs/", "/logs/", 
            "/app/logs/", "/app/var/log", "/var/www/",
            "/storage/logs/", "/tmp/log"
        ];
        
        log_directories.iter().any(|&dir| path_lower.contains(dir))
    }

    /// Vérifie si un fichier pourrait être du texte (pas binaire)
    fn could_be_text_file(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        
        // Exclusions définitives (fichiers binaires/inutiles)
        let binary_extensions = [
            ".so", ".bin", ".exe", ".dll", ".dylib",
            ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
            ".mp3", ".mp4", ".avi", ".pdf", ".zip", ".tar",
            ".gz", ".bz2", ".xz", ".deb", ".rpm"
        ];
        
        // Si c'est un fichier binaire connu, on ignore
        if binary_extensions.iter().any(|&ext| path_lower.ends_with(ext)) {
            return false;
        }

        // Exclusions par path
        let excluded_paths = [
            "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
            "/usr/lib/", "/lib/", "/lib64/",
            "/boot/", "/media/", "/mnt/"
        ];
        
        !excluded_paths.iter().any(|&excluded| path_lower.starts_with(excluded))
    }

    /// Analyse le contenu pour déterminer si c'est vraiment des logs
    fn content_looks_like_logs(&self, sample_content: &str) -> bool {
        if sample_content.trim().is_empty() {
            return false;
        }

        // Patterns qui indiquent fortement des logs
        let strong_log_indicators = [
            // Timestamps
            r"\d{4}-\d{2}-\d{2}",                    // 2024-08-15
            r"\d{2}/\w{3}/\d{4}",                    // 15/Aug/2024
            r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", // [2024-08-15T10:30:00
            
            // Log levels
            r"\b(INFO|WARN|WARNING|ERROR|DEBUG|TRACE|FATAL|NOTICE)\b",
            r"\[(INFO|WARN|ERROR|DEBUG)\]",
            
            // HTTP logs
            r"\b(GET|POST|PUT|DELETE|PATCH)\s+/",
            r"HTTP/1\.[01]",
            r"\b(200|201|301|302|400|401|403|404|500|502|503)\b",
            
            // Application logs
            r"\bException\b",
            r"\bat\s+\w+\.\w+:\d+",
            r"Stack trace:",
        ];

        let indicator_count = strong_log_indicators.iter()
            .filter(|&pattern| {
                regex::Regex::new(pattern)
                    .map(|re| re.is_match(sample_content))
                    .unwrap_or(false)
            })
            .count();

        // Si on trouve au moins 2 patterns, c'est probablement des logs
        indicator_count >= 2
    }


    /// Méthode helper pour exécuter les commandes
    async fn execute_simple_command(&self, container_id: &str, cmd: Vec<&str>) -> Result<Vec<String>> {
        let exec_config = CreateExecOptions {
            cmd: Some(cmd),
            attach_stdout: Some(true),
            attach_stderr: Some(false),
            ..Default::default()
        };

        let exec = self.docker.create_exec(container_id, exec_config).await?;
        
        let mut output_string = String::new();
        let stream = self.docker.start_exec(&exec.id, None).await?;

        match stream {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(chunk) = output.next().await {
                    if let Ok(log_output) = chunk {
                        let bytes = log_output.into_bytes();
                        output_string.push_str(&String::from_utf8_lossy(&bytes));
                    }
                }
            }
            StartExecResults::Detached => {
                return Err(anyhow!("Exec détaché"));
            }
        }
        
        let files: Vec<String> = output_string
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect();

        Ok(files)
    }


    /// Analyse un fichier pour déterminer son type et s'il est actif
    async fn analyze_log_file(
        &self,
        container_id: &str,
        container_name: &str,
        file_path: &str
    ) -> Result<LogFileSource> {
        let (size_bytes, is_active) = self.get_file_info(container_id, file_path).await?;
        let sample_content = self.read_sample_lines(container_id, file_path, 10).await
            .unwrap_or_else(|_| String::new());
        let category = Self::detect_category_from_content(&sample_content);
        let file_name = file_path
            .split('/')
            .last()
            .unwrap_or("unknown")
            .to_string();

        Ok(LogFileSource {
            container_id: container_id.to_string(),
            container_name: container_name.to_string(),
            file_path: file_path.to_string(),
            file_name,
            category,
            is_active,
            size_bytes,
            sample_content,
        })
    }

    /// Récupère taille et timestamp de modification
    // async fn get_file_info(&self, container_id: &str, file_path: &str) -> Result<(u64, bool)> {
    //     let exec_config = CreateExecOptions {
    //         cmd: Some(vec!["stat", "-c", "%s %Y", file_path]),
    //         attach_stdout: Some(true),
    //         ..Default::default()
    //     };
    //
    //     let exec = self.docker.create_exec(container_id, exec_config).await?;
    //
    //     let mut output_string = String::new();
    //     let stream = self.docker.start_exec(&exec.id, None).await?;
    //
    //     match stream {
    //         StartExecResults::Attached { mut output, .. } => {
    //             while let Some(chunk) = output.next().await {
    //                 if let Ok(log_output) = chunk {
    //                     let bytes = log_output.into_bytes();
    //                     output_string.push_str(&String::from_utf8_lossy(&bytes));
    //                 }
    //             }
    //         }
    //         StartExecResults::Detached => {
    //             return Err(anyhow!("Exec détaché"));
    //         }
    //     }
    //
    //     let parts: Vec<&str> = output_string.trim().split_whitespace().collect();
    //     if parts.len() >= 2 {
    //         let size_bytes = parts[0].parse::<u64>().unwrap_or(0);
    //         let timestamp = parts[1].parse::<i64>().unwrap_or(0);
    //         let now = Utc::now().timestamp();
    //         let is_active = (now - timestamp) < 3600;
    //         Ok((size_bytes, is_active))
    //     } else {
    //         Err(anyhow!("Impossible de parser les infos du fichier"))
    //     }
    // }
    async fn get_file_info(&self, container_id: &str, file_path: &str) -> Result<(u64, bool)> {
        let exec_config = CreateExecOptions {
            cmd: Some(vec!["stat", "-c", "%s %Y", file_path]),
            attach_stdout: Some(true),
            ..Default::default()
        };

        let exec = self.docker.create_exec(container_id, exec_config).await?;

        let mut output_string = String::new();
        let stream = self.docker.start_exec(&exec.id, None).await?;

        match stream {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(chunk) = output.next().await {
                    if let Ok(log_output) = chunk {
                        let bytes = log_output.into_bytes();
                        output_string.push_str(&String::from_utf8_lossy(&bytes));
                    }
                }
            }
            StartExecResults::Detached => {
                return Err(anyhow!("Exec détaché"));
            }
        }

        let parts: Vec<&str> = output_string.trim().split_whitespace().collect();
        if parts.len() >= 2 {
            let size_bytes = parts[0].parse::<u64>().unwrap_or(0);
            let timestamp = parts[1].parse::<i64>().unwrap_or(0);
            let now = Utc::now().timestamp();
            let age_seconds = now - timestamp;

            // DÉBUGAGE : Affiches les infos
            // println!("      🔧 DEBUG: {} - Taille: {} bytes, Âge: {}s",
            //          file_path, size_bytes, age_seconds);

            // Relâche la contrainte : 24 heures au lieu d'1 heure
            let is_active = age_seconds < 86400;  // 24 heures

            Ok((size_bytes, is_active))
        } else {
            Err(anyhow!("Impossible de parser les infos du fichier: '{}'", output_string))
        }
    }

    /// Lit les premières lignes d'un fichier pour analyse
    async fn read_sample_lines(&self, container_id: &str, file_path: &str, num_lines: usize) -> Result<String> {
        let num_lines_str = num_lines.to_string();
        let exec_config = CreateExecOptions {
            cmd: Some(vec!["head", "-n", &num_lines_str, file_path]),
            attach_stdout: Some(true),
            attach_stderr: Some(false),
            ..Default::default()
        };

        let exec = self.docker.create_exec(container_id, exec_config).await?;

        let mut output_string = String::new();
        let stream = self.docker.start_exec(&exec.id, None).await?;

        match stream {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(chunk) = output.next().await {
                    if let Ok(log_output) = chunk {
                        let bytes = log_output.into_bytes();
                        output_string.push_str(&String::from_utf8_lossy(&bytes));
                    }
                }
            }
            StartExecResults::Detached => {
                return Err(anyhow!("Exec détaché"));
            }
        }

        Ok(output_string)
    }

    /// Détecte le type de logs selon le contenu
    fn detect_category_from_content(sample: &str) -> LogCategory {
        let sample_lower = sample.to_lowercase();

        if Self::looks_like_web_logs(&sample_lower) {
            LogCategory::WebServer
        } else if Self::looks_like_database_logs(&sample_lower) {
            LogCategory::Database
        } else if Self::looks_like_application_logs(&sample_lower) {
            LogCategory::Application
        } else {
            LogCategory::System
        }
    }

    /// Détecte les logs de serveur web (Nginx, Apache, Caddy)
    fn looks_like_web_logs(sample: &str) -> bool {
        let web_patterns = [
            r"\b(get|post|put|delete|head|options)\b",
            r"\b(200|201|301|302|400|401|403|404|500|502|503)\b",
            r"\d+\.\d+\.\d+\.\d+",
            r"(mozilla|chrome|safari|curl|wget)",
            r"\S+\s+\d{3}\s+\d+",
            r"(nginx|apache|caddy)",
        ];

        let matches = web_patterns.iter()
            .filter(|&pattern| {
                Regex::new(pattern).unwrap().is_match(sample)
            })
            .count();

        matches >= 2
    }

    /// Détecte les logs de base de données
    fn looks_like_database_logs(sample: &str) -> bool {
        let db_patterns = [
            r"\b(select|insert|update|delete|create|drop|alter)\b",
            r"\b(connection|query|statement|transaction)\b",
            r"\b(postgresql|postgres|mysql|mariadb|redis|mongodb)\b",
            r"\b(log:|error:|warning:|notice:)\b",
            r"\b(database|schema|table|index)\b",
        ];

        let matches = db_patterns.iter()
            .filter(|&pattern| {
                Regex::new(pattern).unwrap().is_match(sample)
            })
            .count();

        matches >= 2
    }

    /// Détecte les logs d'application (Symfony, etc.)
    fn looks_like_application_logs(sample: &str) -> bool {
        let app_patterns = [
            r"\[(.*?)\].*\.(info|error|warning|debug):",
            r#"\{.*"level".*"message".*\}"#,
            r"\b(exception|error|warning|info|debug)\b",
            r"\b(stack trace|at line \d+|in file)\b",
            r"\b(symfony|laravel|doctrine|monolog)\b",
            r"\b(app\.php|index\.php|bootstrap)\b",
        ];

        let matches = app_patterns.iter()
            .filter(|&pattern| {
                Regex::new(pattern).unwrap().is_match(sample)
            })
            .count();

        matches >= 2
    }
}