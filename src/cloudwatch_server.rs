// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
use anyhow::Result;
use aws_config::SdkConfig;
use aws_sdk_cloudwatch::{Client, types::{Dimension, Statistic, ComparisonOperator}};
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
use std::time::{SystemTime, Duration};

// Structure to hold metric data
#[derive(Debug, Serialize)]
struct MetricData {
    label: String,
    timestamps: Vec<String>,
    values: Vec<f64>,
}

// Response structure for metric queries
#[derive(Debug, Serialize)]
struct MetricQueryResponse {
    metrics: Vec<MetricData>,
    error: Option<String>,
}

// Structure to hold alarm information
#[derive(Debug, Serialize)]
struct AlarmInfo {
    name: String,
    description: Option<String>,
    namespace: Option<String>,
    metric_name: Option<String>,
    state: Option<String>,
    threshold: Option<f64>,
    comparison_operator: Option<String>,
    evaluation_periods: Option<i32>,
}

// Response structure for alarm listing
#[derive(Debug, Serialize)]
struct AlarmListResponse {
    alarms: Vec<AlarmInfo>,
}

// Response structure for alarm operations
#[derive(Debug, Serialize)]
struct AlarmOperationResponse {
    alarm_name: String,
    operation: String,
    status: String,
    message: String,
}

#[derive(Debug, Clone)]
pub struct CloudWatchOperator {
    config: SdkConfig,
}

impl CloudWatchOperator {
    pub async fn new() -> Self {
        // Load default AWS configuration
        let config = aws_config::from_env().load().await;
        Self { config }
    }

    // Helper method to create a CloudWatch client for a specific region
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
impl CloudWatchOperator {
    #[tool(description = "Get CloudWatch metric data")]
    async fn get_metric_data(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to get metrics from")]
        region: String,
        
        #[tool(param)]
        #[schemars(description = "CloudWatch namespace (e.g., AWS/EC2, AWS/RDS)")]
        namespace: String,
        
        #[tool(param)]
        #[schemars(description = "Metric name (e.g., CPUUtilization)")]
        metric_name: String,
        
        #[tool(param)]
        #[schemars(description = "Statistic to retrieve (e.g., Average, Maximum, Minimum, Sum, SampleCount)")]
        statistic: String,
        
        #[tool(param)]
        #[schemars(description = "Period in seconds (e.g., 60, 300, 3600)")]
        period: i32,
        
        #[tool(param)]
        #[schemars(description = "Start time in minutes ago (e.g., 60 for 1 hour ago)")]
        start_time_minutes_ago: u64,
        
        #[tool(param)]
        #[schemars(description = "End time in minutes ago (e.g., 0 for now)")]
        end_time_minutes_ago: u64,
        
        #[tool(param)]
        #[schemars(description = "Dimension name (e.g., InstanceId)")]
        dimension_name: Option<String>,
        
        #[tool(param)]
        #[schemars(description = "Dimension value (e.g., i-1234567890abcdef0)")]
        dimension_value: Option<String>,
    ) -> Json<MetricQueryResponse> {
        tracing::info!("Getting CloudWatch metric data for {}/{} in region {}...", namespace, metric_name, region);

        let client = self.get_client(&region).await;
        
        // Calculate start and end times
        let now = SystemTime::now();
        let start_time = now.checked_sub(Duration::from_secs(start_time_minutes_ago * 60))
            .unwrap_or(now);
        let end_time = now.checked_sub(Duration::from_secs(end_time_minutes_ago * 60))
            .unwrap_or(now);
        
        // Create dimensions if provided
        let mut dimensions = Vec::new();
        if let (Some(name), Some(value)) = (dimension_name, dimension_value) {
            dimensions.push(
                Dimension::builder()
                    .name(name)
                    .value(value)
                    .build(),
            );
        }
        
        // Parse statistic
        let stat = match statistic.as_str() {
            "Average" => Statistic::Average,
            "Maximum" => Statistic::Maximum,
            "Minimum" => Statistic::Minimum,
            "Sum" => Statistic::Sum,
            "SampleCount" => Statistic::SampleCount,
            _ => {
                tracing::error!("Invalid statistic: {}", statistic);
                return Json(MetricQueryResponse { metrics: vec![], error: Some(format!("Invalid statistic: {}", statistic)) });
            }
        };
        
        // Execute query
        match client.get_metric_statistics()
            .namespace(namespace.clone())
            .metric_name(metric_name.clone())
            .set_dimensions(Some(dimensions))
            .statistics(stat)
            .period(period)
            .start_time(start_time.into())
            .end_time(end_time.into())
            .send()
            .await {
                
            Ok(resp) => {
                let mut metrics = Vec::new();
                
                if let Some(datapoints) = resp.datapoints() {
                    let mut timestamps = Vec::new();
                    let mut values = Vec::new();
                    
                    for datapoint in datapoints {
                        if let Some(timestamp) = datapoint.timestamp() {
                            // Format timestamp as string
                            let ts_str = format!("{:?}", timestamp);
                            timestamps.push(ts_str);
                            
                            // Get the value based on the statistic
                            let value = match statistic.as_str() {
                                "Average" => datapoint.average().unwrap_or(0.0),
                                "Maximum" => datapoint.maximum().unwrap_or(0.0),
                                "Minimum" => datapoint.minimum().unwrap_or(0.0),
                                "Sum" => datapoint.sum().unwrap_or(0.0),
                                "SampleCount" => datapoint.sample_count().unwrap_or(0.0),
                                _ => 0.0,
                            };
                            
                            values.push(value);
                        }
                    }
                    
                    metrics.push(MetricData {
                        label: format!("{}/{}", namespace, metric_name),
                        timestamps,
                        values,
                    });
                }
                
                tracing::info!("Successfully retrieved metric data for {}/{}", namespace, metric_name);
                Json(MetricQueryResponse { metrics, error: None })
            }
            Err(err) => {
                // 添加更詳細的錯誤日誌
                tracing::error!("Failed to get metric data: {:?}", err);
                tracing::error!("Request parameters: region={}, namespace={}, metric_name={}, start_time_minutes_ago={}, end_time_minutes_ago={}", 
                    region, namespace, metric_name, start_time_minutes_ago, end_time_minutes_ago);
                
                // 返回錯誤信息
                Json(MetricQueryResponse { 
                    metrics: vec![],
                    error: Some(format!("Error: {:?}", err))
                })
            }
        }
    }
    
    #[tool(description = "List CloudWatch alarms")]
    async fn list_alarms(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to list alarms from")]
        region: String,
    ) -> Json<AlarmListResponse> {
        tracing::info!("Listing CloudWatch alarms in region: {}...", region);

        let client = self.get_client(&region).await;

        match client.describe_alarms().send().await {
            Ok(resp) => {
                let alarms = resp
                    .metric_alarms()
                    .unwrap_or_default()
                    .iter()
                    .map(|alarm| {
                        AlarmInfo {
                            name: alarm.alarm_name().unwrap_or_default().to_string(),
                            description: alarm.alarm_description().map(String::from),
                            namespace: alarm.namespace().map(String::from),
                            metric_name: alarm.metric_name().map(String::from),
                            state: alarm.state_value().map(|s| format!("{:?}", s)),
                            threshold: alarm.threshold(),
                            comparison_operator: alarm.comparison_operator().map(|op| format!("{:?}", op)),
                            evaluation_periods: alarm.evaluation_periods(),
                        }
                    })
                    .collect::<Vec<AlarmInfo>>();

                tracing::info!(
                    "Successfully listed {} CloudWatch alarms in region {}",
                    alarms.len(),
                    region
                );
                Json(AlarmListResponse { alarms })
            }
            Err(err) => {
                tracing::error!("Failed to list CloudWatch alarms: {:?}", err);
                Json(AlarmListResponse { alarms: vec![] })
            }
        }
    }
    
    #[tool(description = "Create a new CloudWatch alarm")]
    async fn create_alarm(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to create alarm in")]
        region: String,
        
        #[tool(param)]
        #[schemars(description = "Alarm name")]
        alarm_name: String,
        
        #[tool(param)]
        #[schemars(description = "Alarm description")]
        description: String,
        
        #[tool(param)]
        #[schemars(description = "CloudWatch namespace (e.g., AWS/EC2, AWS/RDS)")]
        namespace: String,
        
        #[tool(param)]
        #[schemars(description = "Metric name (e.g., CPUUtilization)")]
        metric_name: String,
        
        #[tool(param)]
        #[schemars(description = "Statistic to use (e.g., Average, Maximum, Minimum, Sum, SampleCount)")]
        statistic: String,
        
        #[tool(param)]
        #[schemars(description = "Period in seconds (e.g., 60, 300, 3600)")]
        period: i32,
        
        #[tool(param)]
        #[schemars(description = "Evaluation periods")]
        evaluation_periods: i32,
        
        #[tool(param)]
        #[schemars(description = "Threshold value")]
        threshold: f64,
        
        #[tool(param)]
        #[schemars(description = "Comparison operator (e.g., GreaterThanThreshold, LessThanThreshold)")]
        comparison_operator: String,
        
        #[tool(param)]
        #[schemars(description = "Dimension name (e.g., InstanceId)")]
        dimension_name: Option<String>,
        
        #[tool(param)]
        #[schemars(description = "Dimension value (e.g., i-1234567890abcdef0)")]
        dimension_value: Option<String>,
    ) -> Json<AlarmOperationResponse> {
        tracing::info!("Creating CloudWatch alarm {} in region {}...", alarm_name, region);

        let client = self.get_client(&region).await;
        
        // Parse statistic
        let stat = match statistic.as_str() {
            "Average" => Statistic::Average,
            "Maximum" => Statistic::Maximum,
            "Minimum" => Statistic::Minimum,
            "Sum" => Statistic::Sum,
            "SampleCount" => Statistic::SampleCount,
            _ => {
                let error_message = format!("Invalid statistic: {}", statistic);
                tracing::error!("{}", error_message);
                return Json(AlarmOperationResponse {
                    alarm_name,
                    operation: "create".to_string(),
                    status: "error".to_string(),
                    message: error_message,
                });
            }
        };
        
        // Parse comparison operator
        let comp_op = match comparison_operator.as_str() {
            "GreaterThanThreshold" => ComparisonOperator::GreaterThanThreshold,
            "LessThanThreshold" => ComparisonOperator::LessThanThreshold,
            "GreaterThanOrEqualToThreshold" => ComparisonOperator::GreaterThanOrEqualToThreshold,
            "LessThanOrEqualToThreshold" => ComparisonOperator::LessThanOrEqualToThreshold,
            _ => {
                let error_message = format!("Invalid comparison operator: {}", comparison_operator);
                tracing::error!("{}", error_message);
                return Json(AlarmOperationResponse {
                    alarm_name,
                    operation: "create".to_string(),
                    status: "error".to_string(),
                    message: error_message,
                });
            }
        };
        
        // Create dimensions if provided
        let mut dimensions = Vec::new();
        if let (Some(name), Some(value)) = (dimension_name, dimension_value) {
            dimensions.push(
                Dimension::builder()
                    .name(name)
                    .value(value)
                    .build(),
            );
        }
        
        // Create alarm
        let mut request = client.put_metric_alarm()
            .alarm_name(alarm_name.clone())
            .alarm_description(description)
            .namespace(namespace)
            .metric_name(metric_name)
            .statistic(stat)
            .period(period)
            .evaluation_periods(evaluation_periods)
            .threshold(threshold)
            .comparison_operator(comp_op);
            
        if !dimensions.is_empty() {
            request = request.set_dimensions(Some(dimensions));
        }
        
        match request.send().await {
            Ok(_) => {
                tracing::info!("Successfully created CloudWatch alarm: {}", alarm_name);
                Json(AlarmOperationResponse {
                    alarm_name,
                    operation: "create".to_string(),
                    status: "success".to_string(),
                    message: "Alarm created successfully".to_string(),
                })
            }
            Err(err) => {
                let error_message = format!("Failed to create CloudWatch alarm: {:?}", err);
                tracing::error!("{}", error_message);
                Json(AlarmOperationResponse {
                    alarm_name,
                    operation: "create".to_string(),
                    status: "error".to_string(),
                    message: error_message,
                })
            }
        }
    }
    
    #[tool(description = "Delete a CloudWatch alarm")]
    async fn delete_alarm(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region where the alarm is located")]
        region: String,
        
        #[tool(param)]
        #[schemars(description = "Alarm name to delete")]
        alarm_name: String,
    ) -> Json<AlarmOperationResponse> {
        tracing::info!("Deleting CloudWatch alarm {} in region {}...", alarm_name, region);

        let client = self.get_client(&region).await;
        
        match client.delete_alarms()
            .alarm_names(alarm_name.clone())
            .send()
            .await {
                
            Ok(_) => {
                tracing::info!("Successfully deleted CloudWatch alarm: {}", alarm_name);
                Json(AlarmOperationResponse {
                    alarm_name,
                    operation: "delete".to_string(),
                    status: "success".to_string(),
                    message: "Alarm deleted successfully".to_string(),
                })
            }
            Err(err) => {
                let error_message = format!("Failed to delete CloudWatch alarm: {:?}", err);
                tracing::error!("{}", error_message);
                Json(AlarmOperationResponse {
                    alarm_name,
                    operation: "delete".to_string(),
                    status: "error".to_string(),
                    message: error_message,
                })
            }
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for CloudWatchOperator {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("CloudWatch metrics and alarms management server".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create log file in /tmp
    let log_path = "/tmp/cloudwatch_operator.log";

    // Setup file logging
    let file_appender = tracing_appender::rolling::never(Path::new("/tmp"), "cloudwatch_operator.log");

    // Initialize the tracing subscriber with both file and stderr logging
    tracing_subscriber::registry()
        .with(
            fmt::Layer::new()
                .with_writer(std::io::stderr.and(file_appender))
                .with_ansi(false),
        )
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    tracing::info!("Starting CloudWatch server... Logs will be saved to {}", log_path);

    // Create an instance of CloudWatch operator
    let service = CloudWatchOperator::new()
        .await
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("Error: {}", e);
        })?;

    service.waiting().await?;

    Ok(())
}