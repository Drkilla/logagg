use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use tokio::time::{Duration, Instant};
use regex;
use serde_json;
use chrono;

use crate::{ContainerInfo, DockerService, LogEntry, LogDiscoverer};
use crate::log_entry::ParsedLogData;

/// État de l'application TUI
pub struct App {
    /// Containers disponibles
    pub containers: Vec<ContainerInfo>,
    
    /// Index du container sélectionné
    pub selected_container: usize,
    
    /// État de la liste des containers
    pub container_list_state: ListState,
    
    /// Logs du container actuel
    pub logs: Vec<LogEntry>,
    
    /// Services
    pub docker_service: DockerService,
    
    /// Découvreur de logs
    pub discoverer: LogDiscoverer,
    
    /// Indique si on doit quitter
    pub should_quit: bool,
    
    /// Dernière mise à jour
    pub last_refresh: Instant,
    
    /// Intervalle de refresh
    pub refresh_interval: Duration,
    
    /// Timestamp du dernier log récupéré (pour éviter les doublons)
    pub last_log_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    
    /// Nombre de logs à charger initialement
    pub tail_lines: u32,
    
    /// Masquer les logs de niveau DEBUG
    pub hide_debug: bool,
    
    /// Forcer l'utilisation des logs Docker
    pub use_docker_logs: bool,
    
    /// Forcer l'utilisation des fichiers de logs
    pub use_file_logs: bool,
}

impl App {
    /// Crée une nouvelle instance de l'app
    pub fn new(refresh_ms: u64, tail_lines: u32, hide_debug: bool, use_docker_logs: bool, use_file_logs: bool) -> Result<Self> {
        let docker_service = DockerService::new()?;
        let docker_client = docker_service.get_client();
        let discoverer = LogDiscoverer::new(docker_client);
        
        let mut container_list_state = ListState::default();
        container_list_state.select(Some(0));

        Ok(Self {
            containers: Vec::new(),
            selected_container: 0,
            container_list_state,
            logs: Vec::new(),
            docker_service,
            discoverer,
            should_quit: false,
            last_refresh: Instant::now(),
            refresh_interval: Duration::from_millis(refresh_ms),
            last_log_timestamp: None,
            tail_lines,
            hide_debug,
            use_docker_logs,
            use_file_logs,
        })
    }

    /// Actualise les données (containers et logs)
    pub async fn refresh(&mut self) -> Result<()> {
        // Actualise la liste des containers
        self.containers = self.docker_service.list_containers().await?;
        
        // Si on a des containers et qu'un est sélectionné
        if !self.containers.is_empty() && self.selected_container < self.containers.len() {
            let container_id = self.containers[self.selected_container].id.clone();
            let container_name = self.containers[self.selected_container].name.clone();
            
            // Découvre et lit les logs du container sélectionné
            self.refresh_logs_for_container(&container_id, &container_name).await?;
        }
        
        self.last_refresh = Instant::now();
        Ok(())
    }

    /// Actualise les logs pour un container donné (depuis les fichiers de logs ou Docker)
    async fn refresh_logs_for_container(&mut self, container_id: &str, container_name: &str) -> Result<()> {
        // Si le mode Docker logs est forcé, va directement aux logs Docker
        if self.use_docker_logs {
            match self.docker_service.get_recent_logs(container_id, container_name.to_string(), self.tail_lines).await {
                Ok(docker_logs) => {
                    self.logs = docker_logs;
                    
                    // Ajoute un message informatif en tête
                    let info_log = crate::LogEntry::new(
                        container_name.to_string(),
                        crate::LogLevel::Info,
                        format!("🐳 Mode Docker logs forcé (--use-docker-logs)"),
                        crate::LogSource::DockerStdout,
                    );
                    self.logs.insert(0, info_log);
                    
                    if let Some(last_log) = self.logs.last() {
                        self.last_log_timestamp = Some(last_log.timestamp);
                    }
                    return Ok(());
                }
                Err(docker_err) => {
                    self.logs.clear();
                    self.logs.push(crate::LogEntry::new(
                        container_name.to_string(),
                        crate::LogLevel::Error,
                        format!("❌ Impossible de lire les logs Docker: {}", docker_err),
                        crate::LogSource::DockerStderr,
                    ));
                    return Ok(());
                }
            }
        }
        
        // Si le mode fichier logs est forcé, va directement aux fichiers
        if self.use_file_logs {
            match self.discoverer.read_log_files(container_id, container_name, self.tail_lines).await {
                Ok(file_logs) => {
                    self.logs = file_logs;
                    
                    // Ajoute un message informatif en tête
                    let info_log = crate::LogEntry::new(
                        container_name.to_string(),
                        crate::LogLevel::Info,
                        format!("📁 Mode fichiers de logs forcé (--use-file-logs)"),
                        crate::LogSource::ApplicationFile { path: "log files".to_string() },
                    );
                    self.logs.insert(0, info_log);
                    
                    // Met à jour le timestamp du dernier log
                    if let Some(last_log) = self.logs.last() {
                        self.last_log_timestamp = Some(last_log.timestamp);
                    }
                    
                    // Limite le nombre de logs affichés pour les performances
                    if self.logs.len() > 2000 {
                        let excess = self.logs.len() - 1000;
                        self.logs.drain(0..excess); // Garde seulement les 1000 plus récents
                    }
                    return Ok(());
                }
                Err(_file_err) => {
                    self.logs.clear();
                    self.logs.push(crate::LogEntry::new(
                        container_name.to_string(),
                        crate::LogLevel::Error,
                        format!("❌ Impossible de lire les fichiers de logs"),
                        crate::LogSource::DockerStderr,
                    ));
                    return Ok(());
                }
            }
        }
        
        // Par défaut, privilégie les logs Docker (plus récents et temps réel)
        match self.docker_service.get_recent_logs(container_id, container_name.to_string(), self.tail_lines).await {
            Ok(docker_logs) => {
                self.logs = docker_logs;
                
                // Ajoute un message informatif en tête pour indiquer la source
                let info_log = crate::LogEntry::new(
                    container_name.to_string(),
                    crate::LogLevel::Info,
                    format!("🐳 Logs Docker temps réel (utilisez --hide-debug pour masquer ce message)"),
                    crate::LogSource::DockerStdout,
                );
                self.logs.insert(0, info_log);
                
                if let Some(last_log) = self.logs.last() {
                    self.last_log_timestamp = Some(last_log.timestamp);
                }
            }
            Err(_docker_err) => {
                // Fallback vers les fichiers de logs si Docker n'est pas accessible
                match self.discoverer.read_log_files(container_id, container_name, self.tail_lines).await {
                    Ok(file_logs) => {
                        self.logs = file_logs;
                        
                        // Ajoute un message informatif en tête
                        let info_log = crate::LogEntry::new(
                            container_name.to_string(),
                            crate::LogLevel::Info,
                            format!("📁 Logs depuis fichiers (Docker inaccessible)"),
                            crate::LogSource::ApplicationFile { path: "log files".to_string() },
                        );
                        self.logs.insert(0, info_log);
                        
                        // Met à jour le timestamp du dernier log
                        if let Some(last_log) = self.logs.last() {
                            self.last_log_timestamp = Some(last_log.timestamp);
                        }
                        
                        // Limite le nombre de logs affichés pour les performances
                        if self.logs.len() > 2000 {
                            let excess = self.logs.len() - 1000;
                            self.logs.drain(0..excess); // Garde seulement les 1000 plus récents
                        }
                    }
                    Err(_file_err) => {
                        self.logs.clear();
                        self.logs.push(crate::LogEntry::new(
                            container_name.to_string(),
                            crate::LogLevel::Error,
                            format!("❌ Impossible de lire les logs: Docker et fichiers inaccessibles"),
                            crate::LogSource::DockerStderr,
                        ));
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Gère les événements clavier
    pub fn handle_key_event(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.previous_container();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.next_container();
            }
            KeyCode::Enter => {
                // Force refresh du container sélectionné
                // On marquera pour actualiser au prochain cycle
            }
            _ => {}
        }
    }

    /// Sélectionne le container précédent
    fn previous_container(&mut self) {
        if !self.containers.is_empty() {
            self.selected_container = if self.selected_container == 0 {
                self.containers.len() - 1
            } else {
                self.selected_container - 1
            };
            self.container_list_state.select(Some(self.selected_container));
            self.logs.clear(); // Clear logs when switching containers
            self.last_log_timestamp = None; // Reset timestamp for new container
        }
    }

    /// Sélectionne le container suivant  
    fn next_container(&mut self) {
        if !self.containers.is_empty() {
            self.selected_container = (self.selected_container + 1) % self.containers.len();
            self.container_list_state.select(Some(self.selected_container));
            self.logs.clear(); // Clear logs when switching containers
            self.last_log_timestamp = None; // Reset timestamp for new container
        }
    }

}

/// Point d'entrée du TUI
pub async fn run_dashboard(refresh_ms: u64, tail_lines: u32, hide_debug: bool, use_docker_logs: bool, use_file_logs: bool) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Crée l'app
    let mut app = App::new(refresh_ms, tail_lines, hide_debug, use_docker_logs, use_file_logs)?;
    
    // Premier refresh
    app.refresh().await?;

    // Boucle principale
    loop {
        // Dessine l'interface
        terminal.draw(|f| ui(f, &mut app))?;

        // Gère les événements avec timeout
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key_event(key.code);
                }
            }
        }

        // Vérifie si on doit quitter
        if app.should_quit {
            break;
        }

        // Actualise périodiquement
        if app.last_refresh.elapsed() >= app.refresh_interval {
            app.refresh().await?;
        }
    }

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

/// Dessine l'interface utilisateur
fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(f.size());

    // Panel de gauche : liste des containers
    draw_container_list(f, app, chunks[0]);
    
    // Panel de droite : logs du container sélectionné
    draw_logs_panel(f, app, chunks[1]);
}

/// Dessine la liste des containers
fn draw_container_list(f: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = app
        .containers
        .iter()
        .enumerate()
        .map(|(i, container)| {
            let style = if i == app.selected_container {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let status_color = match container.status.as_str() {
                s if s.starts_with("Up") => Color::Green,
                _ => Color::Red,
            };

            let content = vec![
                Line::from(vec![
                    Span::styled("🐳 ", Style::default().fg(Color::Blue)),
                    Span::styled(&container.name, style),
                ]),
                Line::from(vec![
                    Span::styled("   ", Style::default()),
                    Span::styled(&container.image, Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::styled("   ", Style::default()),
                    Span::styled(&container.status, Style::default().fg(status_color)),
                ]),
                Line::from(""), // Empty line for spacing
            ];

            ListItem::new(content)
        })
        .collect();

    let title = format!("Containers ({})", app.containers.len());
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(list, area, &mut app.container_list_state);
}

/// Dessine le panel des logs
fn draw_logs_panel(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let title = if !app.containers.is_empty() && app.selected_container < app.containers.len() {
        format!("Logs: {} ({} entries)", 
                app.containers[app.selected_container].name,
                app.logs.len())
    } else {
        "Logs: No container selected".to_string()
    };

    if app.logs.is_empty() {
        // Affiche un message d'aide quand il n'y a pas de logs
        let help_text = if app.containers.is_empty() {
            "No containers found.\nMake sure Docker is running and containers are available."
        } else {
            "No logs available for this container.\nPress Enter to refresh, or use ↑↓ to navigate containers.\n\nPress 'q' to quit."
        };

        let paragraph = Paragraph::new(help_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            )
            .style(Style::default().fg(Color::Gray))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    } else {
        // Affiche les logs avec formatage amélioré (filtre DEBUG si demandé)
        let log_lines: Vec<Line> = app
            .logs
            .iter()
            .filter(|log_entry| {
                // Filtre les logs DEBUG si l'option est activée
                if app.hide_debug && log_entry.level == crate::LogLevel::Debug {
                    false
                } else {
                    true
                }
            })
            .flat_map(|log_entry| {
                let level_style = match log_entry.level {
                    crate::LogLevel::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    crate::LogLevel::Warn => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    crate::LogLevel::Info => Style::default().fg(Color::Green),
                    crate::LogLevel::Debug => Style::default().fg(Color::Gray),
                    crate::LogLevel::Trace => Style::default().fg(Color::DarkGray),
                };

                // Formatage intelligent selon le type de log
                match &log_entry.parsed_data {
                    Some(ParsedLogData::SymfonyLog { channel, message, context, .. }) => {
                        let mut lines = vec![
                            Line::from(vec![
                                Span::styled(
                                    log_entry.timestamp.format("%m-%d %H:%M:%S").to_string(),
                                    Style::default().fg(Color::DarkGray),
                                ),
                                Span::styled(" ", Style::default()),
                                Span::styled(
                                    format!("[{}]", log_entry.level.to_string()),
                                    level_style,
                                ),
                                Span::styled(" ", Style::default()),
                                Span::styled(
                                    format!("[{}] ", channel),
                                    Style::default().fg(Color::Cyan),
                                ),
                                Span::styled(message, Style::default().fg(Color::White)),
                            ])
                        ];

                        // Ajoute le contexte s'il existe et n'est pas vide
                        if !context.is_null() && context != &serde_json::Value::Object(serde_json::Map::new()) {
                            if let Ok(context_str) = serde_json::to_string_pretty(context) {
                                let context_lines: Vec<String> = context_str.lines()
                                    .take(3) // Limite à 3 lignes
                                    .map(|line| line.trim().to_string())
                                    .collect();
                                
                                for context_line in context_lines {
                                    lines.push(Line::from(vec![
                                        Span::styled("         │ ", Style::default().fg(Color::DarkGray)),
                                        Span::styled(context_line, Style::default().fg(Color::Gray)),
                                    ]));
                                }
                            }
                        }
                        lines
                    }
                    Some(ParsedLogData::HttpRequest { method, uri, status, .. }) => {
                        vec![Line::from(vec![
                            Span::styled(
                                log_entry.timestamp.format("%m-%d %H:%M:%S").to_string(),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(" ", Style::default()),
                            Span::styled(
                                format!("[{}]", log_entry.level.to_string()),
                                level_style,
                            ),
                            Span::styled(" ", Style::default()),
                            Span::styled(
                                format!("{} {} ", method, uri),
                                Style::default().fg(Color::White),
                            ),
                            Span::styled(
                                format!("({})", status),
                                if *status >= 400 { 
                                    Style::default().fg(Color::Red) 
                                } else { 
                                    Style::default().fg(Color::Green) 
                                },
                            ),
                        ])]
                    }
                    _ => {
                        // Format basique pour les autres types avec formatage amélioré
                        let formatted_message = format_log_message(&log_entry.message);
                        vec![Line::from(vec![
                            Span::styled(
                                log_entry.timestamp.format("%m-%d %H:%M:%S").to_string(),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(" ", Style::default()),
                            Span::styled(
                                format!("[{}]", log_entry.level.to_string()),
                                level_style,
                            ),
                            Span::styled(" ", Style::default()),
                            Span::styled(formatted_message, Style::default().fg(Color::White)),
                        ])]
                    }
                }
            })
            .collect();

        let paragraph = Paragraph::new(log_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            )
            .wrap(Wrap { trim: true })
            .scroll((0, 0)); // Scroll automatique vers le bas géré par la limitation des logs

        f.render_widget(paragraph, area);
    }
}

/// Formate un message de log pour un affichage plus lisible
fn format_log_message(message: &str) -> String {
    // 1. Supprime le timestamp Docker du début si présent
    let cleaned = remove_docker_timestamp_from_message(message);
    
    // 2. Traite les différents types de logs
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&cleaned) {
        // Log JSON Symfony
        if let Some(msg) = json.get("message").and_then(|m| m.as_str()) {
            if let Some(channel) = json.get("channel").and_then(|c| c.as_str()) {
                return format!("[{}] {}", channel, msg);
            }
            return msg.to_string();
        }
        // Log JSON générique
        if let Some(msg) = json.get("msg").and_then(|m| m.as_str()) {
            return msg.to_string();
        }
    }
    
    // 3. Log PHP-FPM avec messages Symfony - nettoie et extrait l'essentiel
    if cleaned.contains("NOTICE: PHP message:") {
        return format_php_fpm_symfony_message(&cleaned);
    }
    
    // 4. Log PHP-FPM/Nginx - extrait la partie intéressante
    if cleaned.contains("NOTICE:") {
        if let Some(notice_pos) = cleaned.find("NOTICE:") {
            return cleaned[notice_pos..].to_string();
        }
    }
    
    // 5. Log d'accès HTTP - nettoie le format
    if cleaned.contains("POST") || cleaned.contains("GET") || cleaned.contains("PUT") || cleaned.contains("DELETE") {
        return cleaned;
    }
    
    // 6. Fallback : retourne le message nettoyé
    cleaned
}

/// Formate spécifiquement les messages PHP-FPM qui contiennent des logs Symfony
fn format_php_fpm_symfony_message(message: &str) -> String {
    // Format: NOTICE: PHP message: [level] message...
    
    // 1. Cas spécial: Exception Symfony
    if message.contains("Uncaught PHP Exception") {
        if let Some(exception_start) = message.find("Uncaught PHP Exception") {
            let exception_part = &message[exception_start..];
            // Extrait : "Exception: message" at File.php line X
            if let Some(at_pos) = exception_part.find(" at ") {
                let exception_msg = &exception_part[19..at_pos]; // Skip "Uncaught PHP Exception "
                if let Some(quote_end) = exception_msg.rfind('"') {
                    let clean_msg = &exception_msg[..quote_end];
                    if let Some(quote_start) = clean_msg.find('"') {
                        return format!("Exception: {}", &clean_msg[quote_start + 1..]);
                    }
                }
            }
        }
    }
    
    // 2. Messages de debug Symfony - on les ignore ou simplifie
    if message.contains("[debug] Notified event") {
        return "Symfony debug event".to_string();
    }
    
    // 3. Messages Symfony génériques
    if let Some(msg_start) = message.find("PHP message: ") {
        let msg_part = &message[msg_start + 13..]; // Skip "PHP message: "
        
        // Supprime les niveaux de log en brackets
        if msg_part.starts_with('[') {
            if let Some(bracket_end) = msg_part.find(']') {
                let level = &msg_part[1..bracket_end];
                let content = &msg_part[bracket_end + 2..]; // Skip "] "
                
                // Filtre les messages de debug trop verbeux
                if level == "debug" && content.len() > 100 {
                    return format!("[{}] Symfony debug message", level);
                }
                
                return format!("[{}] {}", level, content);
            }
        }
        
        return msg_part.to_string();
    }
    
    // 4. Fallback
    message.to_string()
}

/// Supprime le timestamp Docker du début d'un message
fn remove_docker_timestamp_from_message(message: &str) -> String {
    // Regex pour matcher le timestamp Docker: 2025-08-15T14:37:00.829302466Z
    let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s*").unwrap();
    re.replace(message, "").to_string()
}