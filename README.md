# iot-security-AWS
Cloud-Native IoT Intrusion Detection and Response Pipeline
Overview

This project implements a cloud-native, end-to-end IoT intrusion detection and response pipeline. It integrates on-premises network sensors with AWS-managed services to deliver real-time anomaly detection, graph-based lateral movement analysis, and automated containment via serverless orchestration.

The system spans the full lifecycle:

Data Ingestion: Collect Zeek and Suricata logs from IoT environments.

Feature Engineering: Transform raw logs into time-windowed features using AWS Lambda and DynamoDB.

Anomaly Detection: Deploy a Random Cut Forest (RCF) model on Amazon SageMaker for per-device anomaly scoring.

Graph Analytics: Model internal communications in Amazon Neptune to detect lateral movement.

Automated Response: Orchestrate containment, notification, and rollback using AWS Step Functions.

Architecture
Components

On-Premises Sensor:

Mini-PC with Zeek + Suricata to generate logs.

Vector agent forwards logs to AWS.

Ingestion Layer:

Amazon Kinesis Data Firehose → streams logs to Amazon S3.

Logs partitioned into zeek-logs/ and suricata-logs/.

Feature Engineering:

S3 Event Notifications trigger AWS Lambda.

Lambda parses logs, aggregates features (30–60s windows), stores in:

S3 Data Lake (offline training).

SageMaker Feature Store (real-time inference).

DynamoDB used for stateful aggregation across Lambda invocations.

Detection Layer 1 – Per-Device Anomaly:

SageMaker Random Cut Forest (RCF) for unsupervised anomaly detection.

Lambda publishes anomaly alerts to Amazon EventBridge.

Detection Layer 2 – Lateral Movement Graph:

Amazon Neptune Analytics stores device communication graphs.

Gremlin queries + GraphStorm (Graph ML) used to detect lateral movement.

Response Orchestration:

AWS Step Functions execute the SOAR-lite playbook:

Quarantine device (via Isolation Lambda → network API).

Capture forensic evidence in S3/DynamoDB.

Notify via Amazon SNS (email, Slack, PagerDuty).

Timed rollback or escalation based on new anomalies.

Deployment
Prerequisites

AWS Account with permissions for Lambda, S3, DynamoDB, SageMaker, Neptune, EventBridge, Step Functions, and SNS.

On-premises sensor with Zeek, Suricata, and Vector configured to forward logs.

IAM roles and policies with least-privilege principles applied.

Setup Steps

Provision AWS Resources

Create Kinesis Firehose → S3 bucket for logs.

Configure S3 Event Notifications.

Deploy Lambda functions (Feature Engineering, Scoring, Graph Ingestion, Isolation).

Feature Engineering Pipeline

Configure DynamoDB for window state management.

Update Lambda to write features to S3 + SageMaker Feature Store.

Model Training and Deployment

Train Random Cut Forest (RCF) model with SageMaker Training Jobs.

Deploy model to a SageMaker Endpoint for real-time inference.

Graph Database Setup

Create Neptune cluster.

Load network graph data via Neptune Bulk Loader or direct writes.

Deploy graph queries for lateral movement detection.

Incident Response Playbook

Deploy Step Functions workflow for quarantine, notifications, rollback.

Configure EventBridge rules to trigger workflows on anomaly alerts.

Monitoring & Operations

Amazon CloudWatch monitors Lambda errors, Kinesis delivery metrics, SageMaker endpoint latency, Neptune query performance, and Step Functions execution logs.

False Positive Controls:

Allowlist via DynamoDB.

Cooldowns to prevent flapping.

Multi-layer correlation (require alerts from both anomaly + graph layers).

Roadmap & Stretch Goals

Explainability: Use SageMaker Clarify for SHAP-based feature importance.

TLS Fingerprinting: Integrate Zeek ssl.log for JA3/JA3S analysis.

Dashboard: Build monitoring UI with Athena + QuickSight/Grafana.

Manual Controls: Web interface for manual device release via Step Functions override.