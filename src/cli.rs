use clap::{Parser, Subcommand};

/// Log Aggregator - Agrège les logs Docker et applications
#[derive(Parser)]
#[command(name = "logagg")]
#[command(about = "Agrégateur de logs Docker et applications")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Surveille les logs en temps réel (équivalent de tes commandes Symfony)
    Watch {
        /// Noms des services/containers à surveiller
        #[arg(short, long, value_delimiter = ',')]
        services: Option<Vec<String>>,

        /// Niveaux de log à afficher
        #[arg(short, long, value_delimiter = ',', default_value = "ERROR,WARN,INFO")]
        levels: Vec<String>,

        /// Auto-détection des services via docker-compose
        #[arg(long)]
        auto_detect: bool,

        /// Fichier docker-compose.yml
        #[arg(long, default_value = "docker-compose.yml")]
        compose_file: String,
    },

    /// Interface TUI pour visualiser les logs par container
    Dashboard {
        /// Actualisation en millisecondes
        #[arg(long, default_value = "1000")]
        refresh_ms: u64,
        
        /// Nombre de logs récents à charger initialement
        #[arg(long, default_value = "200")]
        tail_lines: u32,
        
        /// Masquer les logs de niveau DEBUG pour une vue plus claire
        #[arg(long)]
        hide_debug: bool,
        
        /// Forcer l'utilisation des logs Docker (défaut: Docker puis fichiers en fallback)
        #[arg(long)]
        use_docker_logs: bool,
        
        /// Forcer l'utilisation des fichiers de logs au lieu de Docker
        #[arg(long)]
        use_file_logs: bool,
    },

    /// Liste les containers disponibles
    List,
    
    /// Découvre les fichiers de logs dans les containers
    Discover {
        /// Noms des services/containers à surveiller
        #[arg(short, long, value_delimiter = ',')]
        services: Option<Vec<String>>,
    }
}

impl Cli {
    /// Parse les arguments (équivalent de getArgument() en Symfony)
    pub fn parse_args() -> Self {
        Self::parse()
    }
}