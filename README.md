# MCP Sample

A Rust implementation of Model Context Protocol (MCP) servers for extending AI assistant capabilities.

## Overview

This project provides sample MCP servers that can be used with Amazon Q or other MCP-compatible AI assistants. The servers implement various functionalities:

- **Calculator Server**: Performs basic arithmetic operations
- **RDS Server**: Interacts with Amazon RDS instances
- **S3 Server**: Manages Amazon S3 buckets and objects
- **PostgreSQL Server**: Connects to PostgreSQL databases and executes queries

## Prerequisites

- Rust and Cargo
- AWS credentials configured for RDS and S3 operations
- An MCP-compatible AI assistant (like Amazon Q)

## Installation

Clone the repository and build the project:

```bash
git clone <repository-url>
cd mcp-sample
cargo build
```

## Usage

Build the executable files for each server:

```bash
# Build the calculator server
cargo build --release --bin calculator_server

# Build the RDS server
cargo build --release --bin rds_server

# Build the S3 server
cargo build --release --bin s3_server

# Build the PostgreSQL server
cargo build --release --bin postgresql_server
```

After building, you can run each server independently:

```bash
# Run the calculator server
./target/release/calculator_server

# Run the RDS server
./target/release/rds_server

# Run the S3 server
./target/release/s3_server

# Run the PostgreSQL server (requires a connection string)
./target/release/postgresql_server "postgresql://username:password@hostname:port/database"
```

### Integration with Amazon Q CLI

To integrate these MCP servers with Amazon Q CLI or other MCP-compatible clients, add a configuration like this to your `.amazon-q.json` file:

```json
{
  "mcpServers": {
    "calculator": {
      "command": "/path/to/mcp-sample-servers-rust/target/release/calculator_server",
      "args": []
    },
    "s3": {
      "command": "/path/to/mcp-sample-servers-rust/target/release/s3_server",
      "args": []
    },
    "rds": {
      "command": "/path/to/mcp-sample-servers-rust/target/release/rds_server",
      "args": []
    },
    "postgres": {
      "command": "/path/to/mcp-sample-servers-rust/target/release/postgresql_server",
      "args": ["postgresql://username:password@hostname:port/database"]
    }
  }
}
```

Replace `/path/to/mcp-sample-servers-rust/` with the actual path to your built binaries. Once configured, Amazon Q will be able to use these servers to extend its capabilities.

## Server Descriptions

### Calculator Server

Provides basic arithmetic operations like addition and subtraction.

### RDS Server

Lists and manages Amazon RDS instances in specified regions.

### S3 Server

Manages S3 buckets and objects, including listing buckets by region.

### PostgreSQL Server

Connects to PostgreSQL databases and executes read-only queries, lists tables, and provides schema information.

## Dependencies

- rmcp: Rust implementation of the Model Context Protocol
- AWS SDK for Rust (aws-sdk-s3, aws-sdk-rds, aws-config)
- Tokio for async runtime
- Serde for serialization/deserialization
- tokio-postgres for PostgreSQL database connectivity
