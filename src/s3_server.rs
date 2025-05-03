// hai 02/05/2025
use anyhow::Result;
use aws_config::SdkConfig;
use aws_sdk_s3::Client;
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

// Simple response with just buckets for the modified list_buckets function
#[derive(Debug, Serialize)]
struct SimpleBucketList {
    buckets: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct S3Operator {
    config: SdkConfig,
}

impl S3Operator {
    pub async fn new() -> Self {
        // Load default AWS configuration
        let config = aws_config::from_env().load().await;
        Self { config }
    }

    // Helper method to create an S3 client for a specific region
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
impl S3Operator {
    #[tool(description = "List S3 buckets in a region")]
    async fn list_buckets(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to list buckets from")]
        region: String,
    ) -> Json<SimpleBucketList> {
        tracing::info!("Listing S3 buckets in region: {}...", region);

        let client = self.get_client(&region).await;

        match client.list_buckets().send().await {
            Ok(resp) => {
                let buckets = resp
                    .buckets()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|bucket| bucket.name().map(String::from))
                    .collect::<Vec<String>>();

                tracing::info!(
                    "Successfully listed {} buckets in region {}",
                    buckets.len(),
                    region
                );
                Json(SimpleBucketList { buckets })
            }
            Err(err) => {
                tracing::error!("Failed to list buckets: {:?}", err);
                Json(SimpleBucketList { buckets: vec![] })
            }
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for S3Operator {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("A simple s3 server".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create log file in /tmp
    let log_path = "/tmp/s3_operator.log";

    // Setup file logging
    let file_appender = tracing_appender::rolling::never(Path::new("/tmp"), "s3_operator.log");

    // Initialize the tracing subscriber with both file and stderr logging
    tracing_subscriber::registry()
        .with(
            fmt::Layer::new()
                .with_writer(std::io::stderr.and(file_appender))
                .with_ansi(false),
        )
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    tracing::info!("Starting S3 server... Logs will be saved to {}", log_path);

    // Create an instance of S3 operator
    let service = S3Operator::new()
        .await
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("Error: {}", e);
        })?;

    service.waiting().await?;

    Ok(())
}
