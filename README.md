# AWS-based Wi-Fi hybrid Intrusion Detection & Response System
A hybrid intrusion detection pipeline that monitors network traffic using Zeek and Suricata, detects anomalous activity, and automates incident response using AWS services.
Created by: Lawrence Nguyen, Michael Tran, Rhett Atkin
# Lawrence Nguyen - Cloud Services, Cloud Infrastructure, Security / Detection
* Designed the IDS pipeline architecture, implemented Zeek and Suricata sensors, and developed detection workflows.        
# Michael Tran - Backend Developer, AI algorithm trainer,
* Built the backend services for alert visualization and system monitoring, detection tuning, and incident response automation.
# Project Overview/Pipeline
This project implements an end-to-end intrusion detection and response system designed to simulate a real Security Operations Center (SOC) workflow. The system collects network telemetry from Zeek and Suricata sensors, processes logs in a cloud data pipeline, and applies machine learning and graph analytics to detect anomalous behavior and potential lateral movement.

Alerts trigger automated response playbooks that isolate affected devices, capture forensic evidence, and notify stakeholders.

The goal was to explore how modern cloud-native architectures can support scalable detection, reduce response time, and improve visibility into network activity.
# Key Concepts
* Network Intrusion Detection Systems (NIDS)
* Signature and anomaly-based detection
* Incident response automation
* Defense-in-depth architecture
# Architecture Diagram
* Data Ingestion from network sensors
* Feature engineering pipeline
* Machine learning anomaly detection
* Graph-Based behavioral analysis
* Automated incident response orchestration
* (Add diagram later)
# Tech Stack
* Sensors: Zeek, Suricata
* Cloud Services: AWS Kinesis Data Firehose, Amazon S3, AWS Lambda, DynamoDB, Amazon SageMaker (RCF), SageMaker Feature Store, Amazon Neptune, AWS Step Functions, Amazon SNS / EventBridge, CloudWatch
* Ping Alerts: Discord
# Detection Pipeline
# Data Ingestion
Network Telemetry is collected from Zeek and Suricata sensors and streamed through Kinesis Data Firehose into an S3 data lake for durable storage and processing.
# Feature Engineering
Event-driven Lambda functions parse log data, generate time-windowed behavioral features, and store results in both S3 for training and SageMaker Feature Store for real-time inference.
# Machine Learning Detection
A Random Cut Forest model deployed via SageMaker analyzes device behavior to generate anomaly scores and detect deviations from normal traffic patterns.
# Lateral Movement Detection
Network connections are modeled as a graph using Amazon Neptune, enabling detection of suspicious communication patterns such as new internal connections, risky port usage, and abnormal fan-in behavior. 
This layer helps identify sophisticated attacks that may not be detected through per-device anomaly analysis alone.
# Incident Response Workflow
High-confidence alerts trigger an automated response playbook orchestrated by AWS Step Functions.

The workflow:
* Isolates affected devices
* Captures forensic evidence
* Sends notifications to Discord.
* Implements rollback after a defined period
# Monitoring & Reliability
System health and performance are monitored using CloudWatch metrics and logs, enabling visibility into pipeline performance, detection latency, and workflow execution.
# Challenges & Lessons Learned
* Designing scalable event-driven pipelines
* Managing state for time-windowed feature aggregation
* Balancing detection sensitivity with false positives
* Understanding normal vs anomalous network behavior
* Integrating multiple detection layers
* AWS costs and management.
# Future improvements
* Add threat intelligence feeds
* Build SIEM dashboard visualizations
* Add TLS fingerprinting
* Improve alert correlation across detection layers
