// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
use anyhow::Result;
use aws_config::SdkConfig;
use aws_sdk_securityhub::{Client as SecurityHubClient, types::SeverityLabel};
use aws_sdk_config::{Client as ConfigClient};
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

// Structure to hold security finding data
#[derive(Debug, Serialize)]
struct SecurityFinding {
    id: String,
    title: String,
    description: String,
    severity: String,
    resource_id: String,
    resource_type: String,
    created_at: String,
    updated_at: String,
}

// Response structure for security findings
#[derive(Debug, Serialize)]
struct SecurityFindingsResponse {
    findings: Vec<SecurityFinding>,
    error: Option<String>,
}

// Structure to hold CIS compliance check result
#[derive(Debug, Serialize)]
struct ComplianceCheck {
    rule_id: String,
    title: String,
    status: String,
    resource_id: String,
    resource_type: String,
    last_evaluated: String,
}

// Response structure for compliance checks
#[derive(Debug, Serialize)]
struct ComplianceChecksResponse {
    checks: Vec<ComplianceCheck>,
    error: Option<String>,
}

// Structure to hold security score data
#[derive(Debug, Serialize)]
struct SecurityScore {
    category: String,
    score: f64,
    max_score: f64,
    critical_findings: i32,
    high_findings: i32,
    medium_findings: i32,
    low_findings: i32,
}

// Response structure for security score
#[derive(Debug, Serialize)]
struct SecurityScoreResponse {
    scores: Vec<SecurityScore>,
    overall_score: f64,
    error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityOpsOperator {
    config: SdkConfig,
}

impl SecurityOpsOperator {
    pub async fn new() -> Self {
        // Load default AWS configuration
        let config = aws_config::from_env().load().await;
        Self { config }
    }

    // Helper method to create a SecurityHub client for a specific region
    async fn get_securityhub_client(&self, region_str: &str) -> SecurityHubClient {
        if !region_str.is_empty() {
            let region = Region::new(region_str.to_string());
            let config = aws_config::from_env().region(region).load().await;
            SecurityHubClient::new(&config)
        } else {
            SecurityHubClient::new(&self.config)
        }
    }

    // Helper method to create a Config client for a specific region
    async fn get_config_client(&self, region_str: &str) -> ConfigClient {
        if !region_str.is_empty() {
            let region = Region::new(region_str.to_string());
            let config = aws_config::from_env().region(region).load().await;
            ConfigClient::new(&config)
        } else {
            ConfigClient::new(&self.config)
        }
    }
}

#[tool(tool_box)]
impl SecurityOpsOperator {
    #[tool(description = "Get security findings from AWS Security Hub")]
    async fn get_security_findings(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to get findings from")]
        region: String,
        
        #[tool(param)]
        #[schemars(description = "Severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, or ALL)")]
        severity: String,
        
        #[tool(param)]
        #[schemars(description = "Maximum number of findings to return (1-100)")]
        max_items: i32,
        
        #[tool(param)]
        #[schemars(description = "Filter by resource type (e.g., AwsEc2Instance, AwsS3Bucket)")]
        resource_type: Option<String>,
    ) -> Json<SecurityFindingsResponse> {
        tracing::info!("Getting security findings from region {} with severity {}...", region, severity);

        let client = self.get_securityhub_client(&region).await;
        
        // Build filters
        let mut filters = aws_sdk_securityhub::types::AwsSecurityFindingFilters::builder();
        
        // Add severity filter if not ALL
        if severity != "ALL" {
            let severity_label = match severity.as_str() {
                "CRITICAL" => SeverityLabel::Critical,
                "HIGH" => SeverityLabel::High,
                "MEDIUM" => SeverityLabel::Medium,
                "LOW" => SeverityLabel::Low,
                "INFORMATIONAL" => SeverityLabel::Informational,
                _ => {
                    tracing::error!("Invalid severity: {}", severity);
                    return Json(SecurityFindingsResponse {
                        findings: vec![],
                        error: Some(format!("Invalid severity: {}", severity)),
                    });
                }
            };
            
            filters = filters.severity(
                aws_sdk_securityhub::types::SeverityFilter::builder()
                    .eq([severity_label])
                    .build(),
            );
        }
        
        // Add resource type filter if provided
        if let Some(res_type) = resource_type {
            filters = filters.resource_type(
                aws_sdk_securityhub::types::StringFilter::builder()
                    .eq([res_type])
                    .build(),
            );
        }
        
        // Execute query
        match client.get_findings()
            .set_filters(Some(filters.build()))
            .max_results(max_items)
            .send()
            .await {
                
            Ok(resp) => {
                let mut findings = Vec::new();
                
                if let Some(finding_list) = resp.findings() {
                    for finding in finding_list {
                        let id = finding.id().unwrap_or_default().to_string();
                        let title = finding.title().unwrap_or_default().to_string();
                        let description = finding.description().unwrap_or_default().to_string();
                        
                        // Get severity
                        let severity_str = if let Some(severity) = finding.severity() {
                            if let Some(label) = severity.label() {
                                format!("{:?}", label)
                            } else {
                                "UNKNOWN".to_string()
                            }
                        } else {
                            "UNKNOWN".to_string()
                        };
                        
                        // Get resource info
                        let (resource_id, resource_type) = if let Some(resources) = finding.resources() {
                            if let Some(resource) = resources.first() {
                                (
                                    resource.id().unwrap_or_default().to_string(),
                                    resource.type_().unwrap_or_default().to_string(),
                                )
                            } else {
                                ("Unknown".to_string(), "Unknown".to_string())
                            }
                        } else {
                            ("Unknown".to_string(), "Unknown".to_string())
                        };
                        
                        // Get timestamps
                        let created_at = finding.created_at().map_or_else(
                            || "Unknown".to_string(),
                            |ts| format!("{:?}", ts),
                        );
                        
                        let updated_at = finding.updated_at().map_or_else(
                            || "Unknown".to_string(),
                            |ts| format!("{:?}", ts),
                        );
                        
                        findings.push(SecurityFinding {
                            id,
                            title,
                            description,
                            severity: severity_str,
                            resource_id,
                            resource_type,
                            created_at,
                            updated_at,
                        });
                    }
                }
                
                tracing::info!("Successfully retrieved {} security findings", findings.len());
                Json(SecurityFindingsResponse { findings, error: None })
            }
            Err(err) => {
                tracing::error!("Failed to get security findings: {:?}", err);
                Json(SecurityFindingsResponse {
                    findings: vec![],
                    error: Some(format!("Error: {:?}", err)),
                })
            }
        }
    }
    
    #[tool(description = "Get CIS compliance check results")]
    async fn get_cis_compliance(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to get compliance data from")]
        region: String,
        
        #[tool(param)]
        #[schemars(description = "Compliance status filter (COMPLIANT, NON_COMPLIANT, or ALL)")]
        compliance_status: String,
        
        #[tool(param)]
        #[schemars(description = "Maximum number of checks to return (1-100)")]
        max_items: i32,
    ) -> Json<ComplianceChecksResponse> {
        tracing::info!("Getting CIS compliance checks from region {} with status {}...", region, compliance_status);

        let client = self.get_config_client(&region).await;
        
        // Execute query to get AWS Config rules
        match client.describe_config_rules()
            .limit(max_items)
            .send()
            .await {
                
            Ok(rules_resp) => {
                let mut checks = Vec::new();
                
                if let Some(config_rules) = rules_resp.config_rules() {
                    for rule in config_rules {
                        // Only process CIS benchmark rules
                        if let Some(description) = rule.description() {
                            if !description.contains("CIS") {
                                continue;
                            }
                            
                            let rule_id = rule.config_rule_id().unwrap_or_default().to_string();
                            let title = rule.config_rule_name().unwrap_or_default().to_string();
                            
                            // Get compliance details for this rule
                            match client.get_compliance_details_by_config_rule()
                                .config_rule_name(title.clone())
                                .limit(10) // Limit to 10 resources per rule
                                .send()
                                .await {
                                    
                                Ok(compliance_resp) => {
                                    if let Some(results) = compliance_resp.evaluation_results() {
                                        for result in results {
                                            let status = result.compliance_type().map_or_else(
                                                || "UNKNOWN".to_string(),
                                                |ct| format!("{:?}", ct),
                                            );
                                            
                                            // Skip if filtering by status and doesn't match
                                            if compliance_status != "ALL" && status != compliance_status {
                                                continue;
                                            }
                                            
                                            // Get resource info
                                            let resource_id = result.evaluation_result_identifier()
                                                .and_then(|eri| eri.evaluation_result_qualifier())
                                                .and_then(|erq| erq.resource_id())
                                                .unwrap_or_default()
                                                .to_string();
                                                
                                            let resource_type = result.evaluation_result_identifier()
                                                .and_then(|eri| eri.evaluation_result_qualifier())
                                                .and_then(|erq| erq.resource_type())
                                                .unwrap_or_default()
                                                .to_string();
                                                
                                            let last_evaluated = result.result_recorded_time().map_or_else(
                                                || "Unknown".to_string(),
                                                |ts| format!("{:?}", ts),
                                            );
                                            
                                            checks.push(ComplianceCheck {
                                                rule_id,
                                                title: title.clone(),
                                                status,
                                                resource_id,
                                                resource_type,
                                                last_evaluated,
                                            });
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::error!("Failed to get compliance details for rule {}: {:?}", title, err);
                                }
                            }
                        }
                    }
                }
                
                tracing::info!("Successfully retrieved {} CIS compliance checks", checks.len());
                Json(ComplianceChecksResponse { checks, error: None })
            }
            Err(err) => {
                tracing::error!("Failed to get CIS compliance checks: {:?}", err);
                Json(ComplianceChecksResponse {
                    checks: vec![],
                    error: Some(format!("Error: {:?}", err)),
                })
            }
        }
    }
    
    #[tool(description = "Get security score summary")]
    async fn get_security_score(
        &self,
        #[tool(param)]
        #[schemars(description = "AWS region to get security score from")]
        region: String,
    ) -> Json<SecurityScoreResponse> {
        tracing::info!("Getting security score summary from region {}...", region);

        let securityhub_client = self.get_securityhub_client(&region).await;
        
        // Get SecurityHub summary
        match securityhub_client.get_findings_summary().send().await {
            Ok(summary_resp) => {
                let mut scores = Vec::new();
                let mut overall_score = 100.0; // Start with perfect score
                
                // Process finding counts by severity
                let (mut critical, mut high, mut medium, mut low) = (0, 0, 0, 0);
                
                if let Some(severity_counts) = summary_resp.severity_counts() {
                    critical = severity_counts.critical().unwrap_or(0);
                    high = severity_counts.high().unwrap_or(0);
                    medium = severity_counts.medium().unwrap_or(0);
                    low = severity_counts.low().unwrap_or(0);
                }
                
                // Calculate infrastructure security score
                let infra_score = calculate_category_score(critical, high, medium, low);
                overall_score = overall_score.min(infra_score);
                
                scores.push(SecurityScore {
                    category: "Infrastructure Security".to_string(),
                    score: infra_score,
                    max_score: 100.0,
                    critical_findings: critical as i32,
                    high_findings: high as i32,
                    medium_findings: medium as i32,
                    low_findings: low as i32,
                });
                
                // Get CIS compliance score
                let config_client = self.get_config_client(&region).await;
                match config_client.describe_compliance_by_config_rule().send().await {
                    Ok(compliance_resp) => {
                        let mut compliant = 0;
                        let mut non_compliant = 0;
                        
                        if let Some(results) = compliance_resp.compliance_by_config_rules() {
                            for result in results {
                                match result.compliance().map(|c| format!("{:?}", c)).as_deref() {
                                    Some("COMPLIANT") => compliant += 1,
                                    Some("NON_COMPLIANT") => non_compliant += 1,
                                    _ => {}
                                }
                            }
                        }
                        
                        let total_rules = compliant + non_compliant;
                        let compliance_score = if total_rules > 0 {
                            (compliant as f64 / total_rules as f64) * 100.0
                        } else {
                            100.0
                        };
                        
                        overall_score = overall_score.min(compliance_score);
                        
                        scores.push(SecurityScore {
                            category: "CIS Compliance".to_string(),
                            score: compliance_score,
                            max_score: 100.0,
                            critical_findings: 0,
                            high_findings: non_compliant as i32,
                            medium_findings: 0,
                            low_findings: 0,
                        });
                    }
                    Err(err) => {
                        tracing::error!("Failed to get compliance summary: {:?}", err);
                    }
                }
                
                tracing::info!("Successfully calculated security scores");
                Json(SecurityScoreResponse {
                    scores,
                    overall_score,
                    error: None,
                })
            }
            Err(err) => {
                tracing::error!("Failed to get security score: {:?}", err);
                Json(SecurityScoreResponse {
                    scores: vec![],
                    overall_score: 0.0,
                    error: Some(format!("Error: {:?}", err)),
                })
            }
        }
    }
}

// Helper function to calculate security score based on finding counts
fn calculate_category_score(critical: i64, high: i64, medium: i64, low: i64) -> f64 {
    let total_weighted_findings = (critical * 10) + (high * 5) + (medium * 2) + low;
    
    // Calculate score reduction (more findings = lower score)
    let score_reduction = if total_weighted_findings > 100 {
        100.0
    } else {
        total_weighted_findings as f64
    };
    
    100.0 - score_reduction
}

#[tool(tool_box)]
impl ServerHandler for SecurityOpsOperator {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("Security Operations and CIS Compliance server".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create log file in /tmp
    let log_path = "/tmp/security_ops_operator.log";

    // Setup file logging
    let file_appender = tracing_appender::rolling::never(Path::new("/tmp"), "security_ops_operator.log");

    // Initialize the tracing subscriber with both file and stderr logging
    tracing_subscriber::registry()
        .with(
            fmt::Layer::new()
                .with_writer(std::io::stderr.and(file_appender))
                .with_ansi(false),
        )
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    tracing::info!("Starting Security Ops server... Logs will be saved to {}", log_path);

    // Create an instance of Security Ops operator
    let service = SecurityOpsOperator::new()
        .await
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("Error: {}", e);
        })?;

    service.waiting().await?;

    Ok(())
}