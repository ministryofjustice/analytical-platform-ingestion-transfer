import json
import boto3
import os
from datetime import datetime
import logging

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Setup clients
s3_client = boto3.client("s3")
sm_client = boto3.client("secretsmanager")
sns_client = boto3.client("sns")

timestamp = datetime.now().isoformat()
timestamp_epoch = int(datetime.now().timestamp())


def lambda_handler(event, context):
    """
    Lambda function to process GuardDuty Malware Protection scan results

    The function handles multiple scenarios:
    1. When no threats are found (scanResultStatus: NO_THREATS_FOUND)
    2. When threats are found (scanResultStatus: THREATS_FOUND)
    3. When access is denied (scanStatus: ACCESS_DENIED)
    4. When the scan fails (scanStatus: FAILED)
    5. When the file type is unsupported (scanStatus: UNSUPPORTED)
    """
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # Extract the relevant details from the event
        detail = event.get('detail', {})
        scan_status = detail.get('scanStatus')
        scan_result_details = detail.get('scanResultDetails', {})
        scan_result_status = scan_result_details.get('scanResultStatus')

        # Extract S3 object details
        s3_object_details = detail.get('s3ObjectDetails', {})
        bucket_name = s3_object_details.get('bucketName')
        object_key = s3_object_details.get('objectKey')

        # Log the extracted information
        logger.info(f"Scan status: {scan_status}")
        logger.info(f"Scan result status: {scan_result_status}")
        logger.info(f"Bucket name: {bucket_name}")
        logger.info(f"Object key: {object_key}")

        # Default response payload
        response_payload = {
            "bucket": bucket_name,
            "object_key": object_key,
            "scan_status": scan_status,
            "scan_result_status": scan_result_status,
        }

        # Process based on scan status first
        if scan_status == "COMPLETED":

            # If scan completed, process based on the scan result
            if scan_result_status == "NO_THREATS_FOUND":

                if "/" in object_key:
                    supplier, uploaded_object = object_key.split("/", 1)
                    logger.info(f"Supplier: {supplier}")
                    logger.info(f"Object: {uploaded_object}")
                    logger.info(f"Object_key: {object_key}")

                # This section is needed to split out the file name in the case of nested folders
                if "/" in uploaded_object:
                    file_name = uploaded_object.split("/")[-1]
                else:
                    file_name = uploaded_object
                    logger.info(f"File name: {file_name}")

                target_bucket = sm_client.get_secret_value(
                    SecretId=f"ingestion/sftp/{supplier}/target-bucket"
                )["SecretString"]

                if "/" in target_bucket:
                    target_bucket, bucket_prefix = target_bucket.split("/", 1)
                    destination_object_key = f"{bucket_prefix}/{file_name}"
                else:
                    destination_object_key = object_key

                logger.info(f"bucket_prefix: {bucket_prefix}")

                if supplier in ["essex-police"]:
                    destination_object_key = (
                        f"{bucket_prefix}/file_land_timestamp={timestamp_epoch}/{file_name}"
                    )

                copy_source = {"Bucket": "gary-test-123", "Key": object_key}

                s3_client.copy_object(
                    Bucket=target_bucket,
                    CopySource=copy_source,
                    Key=destination_object_key,
                    ACL="bucket-owner-full-control",
                )
                print(
                    f"Successfully copied {object_key} to {target_bucket}/{destination_object_key}"
                )

                # process_clean_file(bucket_name, object_key)

            elif scan_result_status == "THREATS_FOUND":
                threats = scan_result_details.get('threats', [])
                process_infected_file(bucket_name, object_key, threats)

            else:
                logger.warning(f"Unknown scan result status: {scan_result_status}")
        # elif scan_status == "ACCESS_DENIED":
        #     # Handle case when access is denied
        #     process_access_denied(bucket_name, object_key)
        # elif scan_status == "FAILED":
        #     # Handle case when scan fails
        #     process_failed_scan(bucket_name, object_key)
        # elif scan_status == "UNSUPPORTED":
        #     # Handle case when file type is unsupported
        #     process_unsupported_file(bucket_name, object_key)
        # else:
        #     logger.warning(f"Unknown scan status: {scan_status}")

        return {
            'statusCode': 200,
            'body': json.dumps(f"Successfully processed scan status: {scan_status}, result: {scan_result_status}")
        }

        return response_payload

    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error processing event: {str(e)}")
        }

def process_clean_file(bucket_name, object_key):

    logger.info(f"Processing clean file: {object_key} in bucket: {bucket_name}")

    # TODO: this would need to be updated to include a call to secrets manager to collect the destination bucket.
    # TODO: Add cross account lambda permissions to allow this
    clean_bucket = "gary-test-clean"
    # target_bucket = sm_client.get_secret_value(
    #     SecretId=f"ingestion/sftp/{supplier}/target-bucket"
    # )["SecretString"]

    s3_client.copy_object(
        CopySource={'Bucket': bucket_name, 'Key': object_key},
        Bucket=clean_bucket,
        Key=object_key
    )

    s3_client.copy_object(
            Bucket=target_bucket,
            CopySource=copy_source,
            Key=destination_object_key,
            ACL="bucket-owner-full-control",
        )
    # s3_client.delete_object(Bucket=bucket_name, Key=object_key)

    # Placeholder for your implementation
    logger.info("Clean file processing completed")

def process_infected_file(bucket_name, object_key, threats):

    logger.info(f"Processing infected file: {object_key} in bucket: {bucket_name}")
    logger.info(f"Detected threats: {json.dumps(threats)}")

    # Move file to Quarantine bucket, and then delete file.
    quarantine_bucket = os.environ.get('QUARANTINE_BUCKET')
    s3_client.copy_object(
        CopySource={'Bucket': bucket_name, 'Key': object_key},
        Bucket=quarantine_bucket,
        Key=object_key
    )
    s3_client.delete_object(Bucket=bucket_name, Key=object_key)

    # Send Email to user
    topic_arn = os.environ.get('NOTIFICATION_TOPIC_ARN')
    message = f"Automated Malware Protection has detected malware in the file '{object_key}'. \n\nThis file has NOT been transferred, please contact us via Support: \nhttps://github.com/ministryofjustice/data-platform-support/issues \n\nMany thanks, Analytical Platform Team."
    sns_client.publish(
        TopicArn=topic_arn,
        Subject="🚨 Malware Detection Alert",
        Message=message
    )

    # Placeholder for your implementation
    logger.info("Infected file processing completed")

# def process_access_denied(bucket_name, object_key):
#     logger.info(f"Processing access denied for file: {object_key} in bucket: {bucket_name}")

#     # TODO: Implement your specific logic for access denied scenarios
#     # Example: Notify security team, update permissions, log to security dashboard

#     # Placeholder for your implementation
#     logger.info("Access denied processing completed")

# def process_failed_scan(bucket_name, object_key):
#     """
#     Process a case where the scan failed for reasons other than access or file type

#     This function handles scan failures which might require investigation.
#     """
#     logger.info(f"Processing failed scan for file: {object_key} in bucket: {bucket_name}")

#     # TODO: Implement your specific logic for failed scans
#     # Example: Retry scanning, notify administrators, move to error bucket

#     # Placeholder for your implementation
#     logger.info("Failed scan processing completed")

# def process_unsupported_file(bucket_name, object_key):
#     """
#     Process a case where the file type is not supported by the scanner

#     This function handles unsupported file types which cannot be scanned.
#     """
#     logger.info(f"Processing unsupported file: {object_key} in bucket: {bucket_name}")

#     # TODO: Implement your specific logic for unsupported files
#     # Example: Tag as unscannable, move to separate bucket, notify users

#     # Placeholder for your implementation
#     logger.info("Unsupported file processing completed")
