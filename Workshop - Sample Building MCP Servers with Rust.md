# AWS MCP Servers Workshop

This workshop guides you through building and using Model Context Protocol (MCP) servers with Rust to interact with AWS services. By the end of this workshop, you'll understand how to create MCP servers and integrate them with Amazon Q.

## Workshop Overview

1. Introduction to MCP
2. Setting up the environment
3. Building your first MCP server
4. Integrating with AWS services
5. Testing with Amazon Q
6. Advanced topics

## 1. Introduction to MCP

The Model Context Protocol (MCP) is a protocol for communication between AI assistants and external tools. MCP servers provide a standardized way for AI assistants like Amazon Q to interact with external systems and services.

## 2. Setting up the environment

### Prerequisites

- Rust and Cargo installed
- AWS CLI configured with appropriate credentials
- Amazon Q plugin for your IDE
- Git

### Clone the repository

```bash
git clone https://github.com/yourusername/sample-building-mcp-servers-with-rust.git
cd sample-building-mcp-servers-with-rust
```

### Install dependencies

```bash
cargo build
```

## 3. Building your first MCP server

Let's start by examining the calculator server, which is the simplest example:

```rust
// Key components of calculator_server.rs
#[tool(tool_box)]
impl Calculator {
    #[tool(description = "Calculate the sum of two numbers")]
    fn sum(&self, #[tool(aggr)] SumRequest { a, b }: SumRequest) -> String {
        (a + b).to_string()
    }

    #[tool(description = "Calculate the difference of two numbers")]
    fn sub(
        &self,
        #[tool(param)]
        #[schemars(description = "the left hand side number")]
        a: i32,
        #[tool(param)]
        #[schemars(description = "the right hand side number")]
        b: i32,
    ) -> Json<i32> {
        Json(a - b)
    }
}
```

### Key concepts:

1. `#[tool(tool_box)]` - Marks an implementation block as containing MCP tools
2. `#[tool(description = "...")]` - Provides a description for a tool function
3. `#[tool(param)]` - Marks a parameter for a tool function
4. `#[schemars(description = "...")]` - Provides a description for a parameter

### Build and run

```bash
cargo run --bin calculator_server
```

## 4. Integrating with AWS services

Now let's look at how to integrate with AWS services using the AWS SDK for Rust.

### Example: RDS Server

The RDS server demonstrates how to interact with Amazon RDS:

```rust
#[tool(tool_box)]
impl RDSOperator {
    #[tool(description = "List RDS instances in a region")]
    async fn list_instances(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to list RDS instances from")]
        region: String,
    ) -> Json<SimpleRDSInstanceList> {
        // Implementation details...
    }
}
```

### Exercise: Add a new function

Try adding a new function to the RDS server to restart an RDS instance:

```rust
#[tool(description = "Restart an RDS instance")]
async fn restart_instance(
    &self,
    #[tool(param)]
    #[schemars(description = "AWS region where the RDS instance is located")]
    region: String,
    
    #[tool(param)]
    #[schemars(description = "RDS instance identifier to restart")]
    instance_identifier: String,
) -> Json<ModifyInstanceResponse> {
    // Implementation details...
}
```

## 5. Testing with Amazon Q

### Configure Amazon Q

Create or edit the Amazon Q configuration file (typically at `~/.aws/amazonq/mcp-config.json`):

```json
{
  "mcpServers": {
    "calculator": {
      "command": "/path/to/calculator_server",
      "args": []
    },
    "rds": {
      "command": "/path/to/rds_server",
      "args": []
    }
  }
}
```

### Test in Amazon Q

1. Open your IDE with Amazon Q plugin
2. Ask Amazon Q to perform operations using your MCP servers:
   - "Calculate the sum of 42 and 58"
   - "List RDS instances in us-east-1"

## 6. Advanced topics

### Creating a CloudWatch MCP server

The CloudWatch server demonstrates more complex interactions:

```rust
#[tool(description = "Get CloudWatch metric data")]
async fn get_metric_data(
    &self,
    #[tool(param)]
    #[schemars(description = "AWS region to get metrics from")]
    region: String,
    
    #[tool(param)]
    #[schemars(description = "CloudWatch namespace (e.g., AWS/EC2, AWS/RDS)")]
    namespace: String,
    
    // More parameters...
) -> Json<MetricQueryResponse> {
    // Implementation details...
}
```

### Exercise: Create an SSO MCP server

Try creating an SSO MCP server that can:
1. List AWS accounts available through SSO
2. List available roles for an account
3. Start device authorization flow for SSO login

## Workshop Challenges

1. **Basic Challenge**: Add a function to the S3 server to list objects in a bucket
2. **Intermediate Challenge**: Create a new MCP server for AWS Lambda that can list and invoke functions
3. **Advanced Challenge**: Create an MCP server for AWS EC2 that can start, stop, and describe instances

## Resources

- [AWS SDK for Rust Documentation](https://docs.rs/aws-sdk-s3/latest/aws_sdk_s3/)
- [Model Context Protocol Specification](https://github.com/modelcontextprotocol/spec)
- [Amazon Q Developer Documentation](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/what-is.html)

## Conclusion

In this workshop, you've learned how to create MCP servers with Rust to interact with AWS services and integrate them with Amazon Q. You can now build your own MCP servers to extend Amazon Q's capabilities with custom tools and AWS service integrations.