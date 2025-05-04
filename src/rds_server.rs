// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
use anyhow::Result;
use aws_config::SdkConfig;
use aws_sdk_rds::Client;
use aws_types::region::Region;
use rmcp::{
    ServerHandler,
    handler::server::wrapper::Json,
    model::{ServerCapabilities, ServerInfo},
    tool,
};
use rmcp::{ServiceExt, transport::stdio};
use serde::Serialize;
use std::path::Path;
use tracing_appender;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{self, EnvFilter, fmt};

// Simple response with just RDS instances
#[derive(Debug, Serialize)]
struct SimpleRDSInstanceList {
    instances: Vec<RDSInstanceInfo>,
}

// Structure to hold RDS instance information
#[derive(Debug, Serialize)]
struct RDSInstanceInfo {
    identifier: String,
    engine: Option<String>,
    status: Option<String>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RDSOperator {
    config: SdkConfig,
}

impl RDSOperator {
    pub async fn new() -> Self {
        // Load default AWS configuration
        let config = aws_config::from_env().load().await;
        Self { config }
    }

    // Helper method to create an RDS client for a specific region
    async fn get_client(&self, region_str: &str) -> Client {
        if !region_str.is_empty() {
            let region = Region::new(region_str.to_string());
            let config = aws_config::from_env().region(region).load().await;
            Client::new(&config)
        } else {
            Client::new(&self.config)
        }
    }
}

#[tool(tool_box)]
impl RDSOperator {
    #[tool(description = "List RDS instances in a region")]
    async fn list_instances(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to list RDS instances from")]
        region: String,
    ) -> Json<SimpleRDSInstanceList> {
        tracing::info!("Listing RDS instances in region: {}...", region);

        let client = self.get_client(&region).await;

        match client.describe_db_instances().send().await {
            Ok(resp) => {
                let instances = resp
                    .db_instances()
                    .unwrap_or_default()
                    .iter()
                    .map(|instance| {
                        let endpoint = instance
                            .endpoint()
                            .and_then(|ep| ep.address())
                            .map(String::from);
                        
                        RDSInstanceInfo {
                            identifier: instance.db_instance_identifier().unwrap_or_default().to_string(),
                            engine: instance.engine().map(String::from),
                            status: instance.db_instance_status().map(String::from),
                            endpoint,
                        }
                    })
                    .collect::<Vec<RDSInstanceInfo>>();

                tracing::info!(
                    "Successfully listed {} RDS instances in region {}",
                    instances.len(),
                    region
                );
                Json(SimpleRDSInstanceList { instances })
            }
            Err(err) => {
                tracing::error!("Failed to list RDS instances: {:?}", err);
                Json(SimpleRDSInstanceList { instances: vec![] })
            }
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for RDSOperator {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("A simple RDS server".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create log file in /tmp
    let log_path = "/tmp/rds_operator.log";

    // Setup file logging
    let file_appender = tracing_appender::rolling::never(Path::new("/tmp"), "rds_operator.log");

    // Initialize the tracing subscriber with both file and stderr logging
    tracing_subscriber::registry()
        .with(
            fmt::Layer::new()
                .with_writer(std::io::stderr.and(file_appender))
                .with_ansi(false),
        )
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    tracing::info!("Starting RDS server... Logs will be saved to {}", log_path);

    // Create an instance of RDS operator
    let service = RDSOperator::new()
        .await
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("Error: {}", e);
        })?;

    service.waiting().await?;

    Ok(())
}
