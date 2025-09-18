import json
import boto3
import os
from datetime import datetime, timezone
from urllib.parse import unquote_plus

# Initialize Boto3 clients outside the handler for reuse
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
# Best practice: Get table name from an environment variable
TABLE_NAME = os.environ.get('TABLE_NAME', 'IotDeviceFeatures') 
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    """
    This function is triggered by an S3 event. It reads the new log file,
    parses the Zeek or Suricata logs line-by-line, and updates 
    aggregated features in a DynamoDB table.
    """
    s3_record = event['Records'][0]['s3']
    bucket_name = s3_record['bucket']['name']
    object_key = unquote_plus(s3_record['object']['key'])

    print(f"Processing file: s3://{bucket_name}/{object_key}")

    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        log_content = response['Body'].read().decode('utf-8')
    except Exception as e:
        print(f"Error getting file from S3: {e}")
        raise e

    # Dictionary to batch updates for efficiency
    updates_to_perform = {} 

    # --- ROBUST PARSING LOGIC (matching notebook approach) ---
    # Handle JSON wrapper format like notebook
    if log_content.strip():
        try:
            # Process JSON wrapper to extract messages
            processed_log_data = '[' + log_content.strip().replace('}{', '},{') + ']'
            data = json.loads(processed_log_data)
            messages = [item['message'] for item in data]
            print(f"Parsed {len(messages)} messages from JSON wrapper")
        except json.JSONDecodeError:
            print("Failed to parse JSON wrapper, trying line by line")
            messages = []
            for line in log_content.strip().splitlines():
                try:
                    log_entry = json.loads(line)
                    if log_entry.get('message'):
                        messages.append(log_entry['message'])
                except json.JSONDecodeError:
                    continue
            print(f"Parsed {len(messages)} messages line by line")

        # Process each message
        processed_count = 0
        for message_str in messages:
            if not message_str:
                continue

            try:
                # --- ZEEK CONN.LOG LOGIC ---
                if object_key.startswith('zeek-logs/') and '\t' in message_str:
                    if message_str.startswith('#'):
                        continue # Skip headers
                    
                    parts = message_str.strip().split('\t')
                    if len(parts) < 10:
                        continue # Skip malformed lines

                    ts = float(parts[0])
                    device_id = parts[2]
                    orig_bytes = int(parts[8]) if parts[8] != '-' else 0
                    resp_bytes = int(parts[9]) if parts[9] != '-' else 0

                    dt_object = datetime.fromtimestamp(ts, tz=timezone.utc)
                    window_ts = dt_object.strftime('%Y-%m-%dT%H:%M:00Z')

                    key = (device_id, window_ts)
                    if key not in updates_to_perform:
                        updates_to_perform[key] = {'conn_count': 0, 'orig_bytes_sum': 0, 'resp_bytes_sum': 0}

                    updates_to_perform[key]['conn_count'] += 1
                    updates_to_perform[key]['orig_bytes_sum'] += orig_bytes
                    updates_to_perform[key]['resp_bytes_sum'] += resp_bytes

                # --- SURICATA ALERT LOGIC ---
                elif 'event_type' in message_str and object_key.startswith('suricata-logs/'):
                    alert = json.loads(message_str)
                    if alert.get('event_type') != 'alert':
                        continue

                    device_id = alert.get('src_ip')
                    ts_str = alert.get('timestamp')
                    
                    if not device_id or not ts_str:
                        continue
                    
                    dt_object = datetime.fromisoformat(ts_str).astimezone(timezone.utc)
                    window_ts = dt_object.strftime('%Y-%m-%dT%H:%M:00Z')

                    key = (device_id, window_ts)
                    if key not in updates_to_perform:
                        updates_to_perform[key] = {'conn_count': 0, 'orig_bytes_sum': 0, 'resp_bytes_sum': 0, 'alert_count': 0}

                    updates_to_perform[key]['alert_count'] += 1
            
            except (json.JSONDecodeError, ValueError, IndexError, KeyError) as e:
                print(f"Skipping malformed message: {message_str[:150]}... Error: {e}")
                continue
            
            processed_count += 1
        
        print(f"Processed {processed_count} valid messages out of {len(messages)} total")

    # Execute the batched updates against DynamoDB
    print(f"Executing {len(updates_to_perform)} DynamoDB updates")
    for (device_id, window_ts), features in updates_to_perform.items():
        try:
            # Build the update expression dynamically based on the features found
            update_expression_parts = []
            expression_attribute_values = {}
            for feature_name, value in features.items():
                update_expression_parts.append(f"{feature_name} :val_{feature_name}")
                expression_attribute_values[f":val_{feature_name}"] = value
            
            update_expression = "ADD " + ", ".join(update_expression_parts)

            print(f"Updating DynamoDB for {device_id} at {window_ts} with expression: {update_expression}")
            table.update_item(
                Key={'DeviceID': device_id, 'WindowTimestamp': window_ts},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values
            )
        except Exception as e:
            print(f"Error updating DynamoDB for {device_id}: {e}")

    return {'statusCode': 200, 'body': 'Processing complete'}