import json
import boto3
import os
import urllib3
from datetime import datetime, timedelta, timezone

# --- CONFIGURATION ---
# TODO: EDIT THIS LINE
# Paste the exact name of your SageMaker endpoint here
SAGEMAKER_ENDPOINT_NAME = "randomcutforest-2025-09-18-17-27-57-413" 
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')
ANOMALY_THRESHOLD = float(os.environ.get('ANOMALY_THRESHOLD', '1.0'))

DYNAMODB_TABLE_NAME = os.environ.get('DYNAMODB_TABLE_NAME', 'IotDeviceFeatures')
FEATURE_COLUMNS = [
    'orig_bytes_sum', 'resp_bytes_sum', 'orig_pkts_sum', 'resp_pkts_sum',
    'duration_mean', 'unique_dest_ips', 'unique_dest_ports', 'conn_count',
    'alert_count', 'unique_alert_signatures'
]

# Initialize boto3 clients
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(DYNAMODB_TABLE_NAME)
sagemaker_runtime = boto3.client('sagemaker-runtime')
http = urllib3.PoolManager()

def send_discord_alert(device_id, anomaly_score, timestamp):
    if not DISCORD_WEBHOOK_URL:
        print("Discord webhook URL is not set. Skipping alert.")
        return
    
    message = {
        "embeds": [{
            "title": "🚨 IoT Security Alert",
            "description": f"High anomaly score detected for device **{device_id}**",
            "color": 15158332,
            "fields": [
                {"name": "Device ID", "value": device_id, "inline": True},
                {"name": "Anomaly Score", "value": f"{anomaly_score:.4f}", "inline": True},
                {"name": "Timestamp", "value": timestamp, "inline": True}
            ]
        }]
    }
    
    try:
        http.request(
            'POST',
            DISCORD_WEBHOOK_URL,
            body=json.dumps(message),
            headers={'Content-Type': 'application/json'}
        )
        print(f"Discord alert sent for {device_id}")
    except Exception as e:
        print(f"Failed to send Discord alert: {e}")

def lambda_handler(event, context):
    """
    This function runs on a schedule. It scans DynamoDB for feature windows
    from the previous minute, invokes a SageMaker endpoint for an anomaly
    score, and prints the result.
    """
    # 1. Calculate the timestamp for the previous minute to query
    now_utc = datetime.now(timezone.utc)
    # Go back 2 minutes to ensure the aggregation window is fully closed
    target_time = now_utc - timedelta(minutes=2) 
    window_to_query = target_time.strftime('%Y-%m-%dT%H:%M:00Z')
    
    print(f"Target time: {target_time}")
    print(f"Window To Query: {window_to_query}")
    print(f"Querying DynamoDB for feature window: {window_to_query}")

    # 2. Scan DynamoDB for all devices in that time window
    try:
        response = table.query(
            IndexName='WindowTimestamp-index', # We will create this index next
            KeyConditionExpression='WindowTimestamp = :ts',
            ExpressionAttributeValues={':ts': window_to_query}
        )
        items = response.get('Items', [])
        
        print(f"Query returned {len(items)} items")
        
    except Exception as e:
        print(f"Error querying DynamoDB: {e}")
        return

    if not items:
        print("No feature sets found for the target window.")
        
        # Fallback: Try to find the most recent timestamp and query that
        print("\nTrying fallback: Finding most recent timestamp...")
        try:
            scan_response = table.scan(Limit=10)
            recent_items = scan_response.get('Items', [])
            if recent_items:
                # Get the most recent timestamp
                timestamps = [item.get('WindowTimestamp') for item in recent_items if item.get('WindowTimestamp')]
                if timestamps:
                    most_recent = max(timestamps)
                    print(f"Most recent timestamp found: {most_recent}")
                    
                    # Query using the most recent timestamp
                    fallback_response = table.query(
                        IndexName='WindowTimestamp-index',
                        KeyConditionExpression='WindowTimestamp = :ts',
                        ExpressionAttributeValues={':ts': most_recent}
                    )
                    items = fallback_response.get('Items', [])
                    print(f"Fallback query found {len(items)} items")
        except Exception as scan_error:
            print(f"Error in fallback scan: {scan_error}")
        
        if not items:
            return

    print(f"Found {len(items)} feature sets to score.")

    # 3. For each item, invoke SageMaker endpoint
    for item in items:
        device_id = item.get('DeviceID')
        
        # Format the features into a CSV string in the correct order
        # Use .get(feature, 0) to handle cases where a feature might be missing
        feature_values = [str(item.get(col, 0)) for col in FEATURE_COLUMNS]
        payload = ",".join(feature_values)

        print(f"Invoking endpoint for Device: {device_id} with payload: {payload}")

        try:
            response = sagemaker_runtime.invoke_endpoint(
                EndpointName=SAGEMAKER_ENDPOINT_NAME,
                ContentType='text/csv',
                Body=payload
            )
            
            result = json.loads(response['Body'].read().decode())
            scores = [score_record['score'] for score_record in result.get('scores', [])]
            
            # --- HANDLE THE SCORE ---
            anomaly_score = scores[0]
            print(f"SUCCESS for {device_id}: Anomaly Score = {anomaly_score}")
            if anomaly_score > ANOMALY_THRESHOLD:
                print(f"ALERT! High anomaly score for device {device_id}!")
                send_discord_alert(device_id, anomaly_score, window_to_query)

        except Exception as e:
            print(f"Error invoking SageMaker endpoint for {device_id}: {e}")

    return {'statusCode': 200, 'body': json.dumps('Scoring complete')}