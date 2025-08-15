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

    /// Liste les containers disponibles
    List,
}

impl Cli {
    /// Parse les arguments (équivalent de getArgument() en Symfony)
    pub fn parse_args() -> Self {
        Self::parse()
    }
}