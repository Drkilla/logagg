use anyhow::Result;
use tokio_stream::StreamExt;

use logagg::{Cli, Commands, DockerService};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse les arguments CLI (équivalent de ton Command handler)
    let cli = Cli::parse_args();

    // Crée le service Docker (équivalent de ton DI container)
    let docker_service = DockerService::new()?;

    match cli.command {
        Commands::List => {
            println!("📋 Containers disponibles:");
            list_containers(&docker_service).await?;
        }
        Commands::Watch {
            services,
            levels: _levels,
            auto_detect,
            compose_file: _compose_file
        } => {
            if auto_detect {
                println!("🔍 Auto-détection des services...");
                watch_all_containers(&docker_service).await?;
            } else if let Some(service_names) = services {
                println!("👀 Surveillance des services: {:?}", service_names);
                watch_specific_services(&docker_service, service_names).await?;
            } else {
                println!("👀 Surveillance de tous les containers...");
                watch_all_containers(&docker_service).await?;
            }
        }
    }

    Ok(())
}

/// Liste tous les containers (équivalent d'une action de Controller)
async fn list_containers(docker_service: &DockerService) -> Result<()> {
    let containers = docker_service.list_containers().await?;

    if containers.is_empty() {
        println!("Aucun container en cours d'exécution.");
        return Ok(());
    }

    println!();
    for container in containers {
        println!(
            "🐳 {} ({})",
            container.name,
            container.image
        );
        println!("   ID: {}", container.id);
        println!("   Status: {}", container.status);
        println!();
    }

    Ok(())
}

/// Surveille tous les containers
async fn watch_all_containers(docker_service: &DockerService) -> Result<()> {
    let containers = docker_service.list_containers().await?;

    if containers.is_empty() {
        println!("Aucun container à surveiller.");
        return Ok(());
    }

    println!("🚀 Démarrage de la surveillance...");
    println!("📡 Containers surveillés:");
    for container in &containers {
        println!("   • {}", container.name);
    }
    println!();

    // Pour commencer, on ne prend que le premier container
    // (on complexifiera après)
    let first_container = &containers[0];
    let mut log_stream = docker_service
        .stream_container_logs(&first_container.id, first_container.name.clone())
        .await?;

    println!("📊 Logs en temps réel (Ctrl+C pour arrêter):");
    println!();

    // Stream infini des logs
    while let Some(log_entry) = log_stream.next().await {
        println!("{}", log_entry.format_colored());
    }

    Ok(())
}

/// Surveille des services spécifiques
async fn watch_specific_services(
    docker_service: &DockerService,
    service_names: Vec<String>,
) -> Result<()> {
    let containers = docker_service.list_containers().await?;

    // Filtre les containers par nom
    let matching_containers: Vec<_> = containers
        .into_iter()
        .filter(|container| {
            service_names.iter().any(|name| container.name.contains(name))
        })
        .collect();

    if matching_containers.is_empty() {
        println!("Aucun container trouvé pour les services: {:?}", service_names);
        return Ok(());
    }

    println!("📡 Services trouvés:");
    for container in &matching_containers {
        println!("   • {}", container.name);
    }
    println!();

    // Pour l'instant, on prend juste le premier
    let first_container = &matching_containers[0];
    let mut log_stream = docker_service
        .stream_container_logs(&first_container.id, first_container.name.clone())
        .await?;

    println!("📊 Logs en temps réel:");
    println!();

    while let Some(log_entry) = log_stream.next().await {
        println!("{}", log_entry.format_colored());
    }

    Ok(())
}