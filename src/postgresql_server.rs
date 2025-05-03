// hai 02/05/2025
use anyhow::{Context, Result};
use rmcp::{
    ServerHandler,
    handler::server::wrapper::Json,
    model::{ServerCapabilities, ServerInfo},
    tool,
};
use rmcp::{ServiceExt, transport::stdio};
use serde::Serialize;
use std::env;
use std::path::Path;
use tokio_postgres::{Client, NoTls};
use tracing_appender;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{self, EnvFilter, fmt};

// Structure to hold table information
#[derive(Debug, Serialize)]
struct TableInfo {
    table_name: String,
}

// Structure to hold column information
#[derive(Debug, Serialize)]
struct ColumnInfo {
    column_name: String,
    data_type: String,
}

// Structure for query results
#[derive(Debug, Serialize)]
struct QueryResult {
    rows: Vec<serde_json::Value>,
}

// We don't need this struct since we're using a direct string parameter in the query function
// Removing to eliminate the dead code warning

#[derive(Debug, Clone)]
pub struct PostgresOperator {
    connection_string: String,
}

impl PostgresOperator {
    pub fn new(connection_string: String) -> Self {
        Self { connection_string }
    }

    // Helper method to create a PostgreSQL client
    async fn get_client(&self) -> Result<Client> {
        let (client, connection) = tokio_postgres::connect(&self.connection_string, NoTls)
            .await
            .context("Failed to connect to PostgreSQL")?;

        // The connection object performs the actual communication with the database,
        // so spawn it off to run on its own
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!("Connection error: {}", e);
            }
        });

        Ok(client)
    }
}

#[tool(tool_box)]
impl PostgresOperator {
    #[tool(description = "List tables in the PostgreSQL database")]
    async fn list_tables(&self) -> Json<Vec<TableInfo>> {
        tracing::info!("Listing tables in PostgreSQL database...");

        match self.get_client().await {
            Ok(client) => {
                match client
                    .query(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
                        &[],
                    )
                    .await
                {
                    Ok(rows) => {
                        let tables = rows
                            .iter()
                            .map(|row| {
                                let table_name: String = row.get("table_name");
                                TableInfo { table_name }
                            })
                            .collect::<Vec<TableInfo>>();

                        tracing::info!("Successfully listed {} tables", tables.len());
                        Json(tables)
                    }
                    Err(err) => {
                        tracing::error!("Failed to list tables: {:?}", err);
                        Json(vec![])
                    }
                }
            }
            Err(err) => {
                tracing::error!("Failed to connect to database: {:?}", err);
                Json(vec![])
            }
        }
    }

    #[tool(description = "Get schema for a specific table")]
    async fn get_table_schema(
        &self,
        #[tool(param)]
        #[schemars(description = "Name of the table to get schema for")]
        table_name: String,
    ) -> Json<Vec<ColumnInfo>> {
        tracing::info!("Getting schema for table: {}...", table_name);

        match self.get_client().await {
            Ok(client) => {
                match client
                    .query(
                        "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = $1",
                        &[&table_name],
                    )
                    .await
                {
                    Ok(rows) => {
                        let columns = rows
                            .iter()
                            .map(|row| {
                                let column_name: String = row.get("column_name");
                                let data_type: String = row.get("data_type");
                                ColumnInfo {
                                    column_name,
                                    data_type,
                                }
                            })
                            .collect::<Vec<ColumnInfo>>();

                        tracing::info!(
                            "Successfully retrieved schema for table {} with {} columns",
                            table_name,
                            columns.len()
                        );
                        Json(columns)
                    }
                    Err(err) => {
                        tracing::error!("Failed to get table schema: {:?}", err);
                        Json(vec![])
                    }
                }
            }
            Err(err) => {
                tracing::error!("Failed to connect to database: {:?}", err);
                Json(vec![])
            }
        }
    }

    #[tool(description = "Run a read-only SQL query")]
    async fn query(
        &self,
        #[tool(param)]
        #[schemars(description = "SQL query to execute (read-only)")]
        sql: String,
    ) -> Json<QueryResult> {
        tracing::info!("Executing SQL query: {}...", sql);

        match self.get_client().await {
            Ok(client) => {
                // Start a read-only transaction
                match client.batch_execute("BEGIN TRANSACTION READ ONLY").await {
                    Ok(_) => {
                        let result = match client.query(&sql, &[]).await {
                            Ok(rows) => {
                                // Convert rows to JSON
                                let json_rows = rows
                                    .iter()
                                    .map(|row| {
                                        let mut json_row = serde_json::Map::new();
                                        for i in 0..row.len() {
                                            if let Some(column_name) =
                                                row.columns()[i].name().to_string().into()
                                            {
                                                // This is a simplification - in a real implementation,
                                                // you would need to handle different data types properly
                                                if let Ok(value) = row.try_get::<_, String>(i) {
                                                    json_row.insert(
                                                        column_name,
                                                        serde_json::Value::String(value),
                                                    );
                                                }
                                            }
                                        }
                                        serde_json::Value::Object(json_row)
                                    })
                                    .collect::<Vec<serde_json::Value>>();

                                tracing::info!(
                                    "Query executed successfully with {} rows",
                                    json_rows.len()
                                );
                                Json(QueryResult { rows: json_rows })
                            }
                            Err(err) => {
                                tracing::error!("Query execution failed: {:?}", err);
                                Json(QueryResult { rows: vec![] })
                            }
                        };

                        // Always rollback the transaction to ensure we don't modify data
                        if let Err(err) = client.batch_execute("ROLLBACK").await {
                            tracing::warn!("Failed to rollback transaction: {:?}", err);
                        }

                        result
                    }
                    Err(err) => {
                        tracing::error!("Failed to start read-only transaction: {:?}", err);
                        Json(QueryResult { rows: vec![] })
                    }
                }
            }
            Err(err) => {
                tracing::error!("Failed to connect to database: {:?}", err);
                Json(QueryResult { rows: vec![] })
            }
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for PostgresOperator {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("A PostgreSQL database server".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Get connection string from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Please provide a PostgreSQL connection string as a command-line argument");
        std::process::exit(1);
    }
    let connection_string = args[1].clone();

    // Create log file in /tmp
    let log_path = "/tmp/postgresql_operator.log";

    // Setup file logging
    let file_appender =
        tracing_appender::rolling::never(Path::new("/tmp"), "postgresql_operator.log");

    // Initialize the tracing subscriber with both file and stderr logging
    tracing_subscriber::registry()
        .with(
            fmt::Layer::new()
                .with_writer(std::io::stderr.and(file_appender))
                .with_ansi(false),
        )
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    tracing::info!(
        "Starting PostgreSQL server... Logs will be saved to {}",
        log_path
    );
    tracing::info!("Using connection string: {}", connection_string);

    // Create an instance of PostgreSQL operator
    let service = PostgresOperator::new(connection_string)
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("Error: {}", e);
        })?;

    service.waiting().await?;

    Ok(())
}
