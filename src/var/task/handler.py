import json
import os
import logging
from datetime import datetime
import boto3

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Setup clients
s3_client = boto3.client("s3")
sm_client = boto3.client("secretsmanager")
sns_client = boto3.client("sns")

timestamp = datetime.now().isoformat()
timestamp_epoch = int(datetime.now().timestamp())


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """
    Lambda function to process GuardDuty Malware Protection scan results

    The function handles multiple scenarios:
    1. When no threats are found (scanResultStatus: NO_THREATS_FOUND)
    2. When threats are found (scanResultStatus: THREATS_FOUND)
    3. When access is denied (scanStatus: ACCESS_DENIED)
    4. When the scan fails (scanStatus: FAILED)
    5. When the file type is unsupported (scanStatus: UNSUPPORTED)
    """
    logger.info("Received event: %s", json.dumps(event))

    try:
        # Extract the relevant details from the event
        detail = event.get("detail", {})
        scan_status = detail.get("scanStatus")
        scan_result_details = detail.get("scanResultDetails", {})
        scan_result_status = scan_result_details.get("scanResultStatus")

        # Extract S3 object details
        s3_object_details = detail.get("s3ObjectDetails", {})
        bucket_name = s3_object_details.get("bucketName")
        object_key = s3_object_details.get("objectKey")

        # Log the extracted information
        logger.info("Scan status: %s", scan_status)
        logger.info("Scan result status: %s", scan_result_status)
        logger.info("Bucket name: %s", bucket_name)
        logger.info("Object key: %s", object_key)

        # Default response payload
        response_payload = {
            "bucket": bucket_name,
            "object_key": object_key,
            "scan_status": scan_status,
            "scan_result_status": scan_result_status,
        }

        # Process based on scan status first
        if scan_status == "COMPLETED":
            if scan_result_status == "NO_THREATS_FOUND":
                process_no_threats_found_file(bucket_name, object_key)
                return {
                    "statusCode": 200,
                    "body": json.dumps(
                        f"Successfully processed - NO THREATS FOUND in file: {object_key} in bucket: {bucket_name}"
                    ),
                }

            if scan_result_status == "THREATS_FOUND":
                threats = scan_result_details.get("threats", [])
                process_threats_found_file(bucket_name, object_key, threats)
                return {
                    "statusCode": 200,
                    "body": json.dumps(
                        f"Successfully processed - THREATS FOUND in file: {object_key} in bucket: {bucket_name}"
                    ),
                }

            logger.warning("Unknown scan result status: %s", scan_result_status)
        elif scan_status == "SKIPPED":
            if scan_result_status == "ACCESS_DENIED":
                process_access_denied(bucket_name, object_key)
                return {
                    "statusCode": 403,
                    "body": json.dumps(
                        f"Error: Access denied to file '{object_key}' in '{bucket_name}'."
                    ),
                }
            if scan_result_status == "UNSUPPORTED":
                process_unsupported_file(bucket_name, object_key)
                return {
                    "statusCode": 415,
                    "body": json.dumps(
                        f"Error: File type is unsupported. Filename: '{object_key}'"
                    ),
                }
        elif scan_status == "FAILED":
            process_failed_scan(bucket_name, object_key)
            return {
                "statusCode": 500,
                "body": json.dumps(f"Error: Scan failed on file '{object_key}'."),
            }
        else:
            logger.warning("Unknown scan status: %s", scan_status)

        return {
            "statusCode": 200,
            "body": json.dumps(
                f"Successfully processed scan status: {scan_status}, result: {scan_result_status}"
            ),
        }

    except Exception as e:
        logger.error("Error processing event: %s", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps(f"Error processing event: {str(e)}"),
        }


def process_no_threats_found_file(bucket_name, object_key):
    """Process files that have been scanned and no threats were found."""
    logger.info(
        "Processing NO_THREATS_FOUND file: %s in bucket: %s",
        object_key,
        bucket_name
    )

    if "/" in object_key:
        supplier, uploaded_object = object_key.split("/", 1)
        logger.info("Supplier: %s", supplier)
        logger.info("Object: %s", uploaded_object)
        logger.info("Object_key: %s", object_key)

    # This section is needed to split out the file name in the case of nested folders
    if "/" in uploaded_object:
        file_name = uploaded_object.split("/")[-1]
    else:
        file_name = uploaded_object
        logger.info("File name: %s", file_name)

    target_bucket = sm_client.get_secret_value(
        SecretId=f"ingestion/sftp/{supplier}/target-bucket"
    )["SecretString"]

    if "/" in target_bucket:
        target_bucket, bucket_prefix = target_bucket.split("/", 1)
        destination_object_key = f"{bucket_prefix}/{file_name}"
    else:
        destination_object_key = object_key

    logger.info("bucket_prefix: %s", bucket_prefix)

    if supplier in ["essex-police"]:
        destination_object_key = (
            f"{bucket_prefix}/file_land_timestamp={timestamp_epoch}/{file_name}"
        )

    copy_source = {"Bucket": os.environ["LANDING_BUCKET_NAME"], "Key": object_key}

    s3_client.copy_object(
        Bucket=target_bucket,
        CopySource=copy_source,
        Key=destination_object_key,
        ACL="bucket-owner-full-control",
    )

    print(
        f"Successfully copied {object_key} to {target_bucket}/{destination_object_key}."
    )

    s3_client.delete_object(Bucket=os.environ["LANDING_BUCKET_NAME"], Key=object_key)

    print(
        f"Successfully deleted {object_key} from {os.environ['LANDING_BUCKET_NAME']}."
    )


def process_threats_found_file(bucket_name, object_key, threats):
    """Process files where threats have been detected."""
    logger.info(
        "Processing THREATS_FOUND - file: '%s' in bucket '%s'",
        object_key,
        bucket_name
    )
    logger.info("Detected threats: %s", json.dumps(threats))

    # Move file to Quarantine bucket, and then delete file.
    quarantine_bucket = os.environ.get("QUARANTINE_BUCKET")
    s3_client.copy_object(
        CopySource={"Bucket": bucket_name, "Key": object_key},
        Bucket=quarantine_bucket,
        Key=object_key,
    )
    s3_client.delete_object(Bucket=bucket_name, Key=object_key)

    # Email user via SNS
    topic_arn = os.environ.get("NOTIFICATION_TOPIC_ARN")
    message = (
        f"Automated Malware Protection has detected malware in the file '{object_key}'.\n\n"
        "This file has NOT been transferred, please contact us via Support:\n"
        "https://github.com/ministryofjustice/data-platform-support/issues\n\n"
        "Many thanks, Analytical Platform Team."
    )
    sns_client.publish(
        TopicArn=topic_arn, Subject="🚨 Malware Detection Alert", Message=message
    )

    # Email Analytical Platform Team via SNS
    topic_arn = os.environ.get("AP_NOTIFICATION_TOPIC_ARN")
    message = (
        f"Automated Malware Protection has detected malware in the file '{object_key}'. \n\n"
        "This file has NOT been transferred, The user has been notified."
        "This alert is to the Analytical Platform Team."
    )
    sns_client.publish(
        TopicArn=topic_arn, Subject="🚨 Malware Detection Alert", Message=message
    )


def process_access_denied(bucket_name, object_key):
    """Process files where scan access was denied."""
    # Email Analytical Platform Team via SNS
    topic_arn = os.environ.get("AP_NOTIFICATION_TOPIC_ARN")
    message = (
        f"The Malware Protection for S3 scan process on file {object_key} has failed due to an 'Access Denied' error. "
        "The user has not been informed, please investigate this at the first opportunity."
    )
    sns_client.publish(
        TopicArn=topic_arn,
        Subject="🚨 Analytical Platform Ingestion: Access Denied Alert",
        Message=message,
    )


def process_failed_scan(bucket_name, object_key):
    """Process files where scanning failed."""
    # Email user via SNS
    topic_arn = os.environ.get("NOTIFICATION_TOPIC_ARN")
    message = (
        f"The Malware Protection for S3 scan process on file {object_key} has failed. \n\n"
        "Please retry by uploading your file again. \n\n"
        "This file has NOT been transferred. If failure persists please contact us via Support: \n"
        "https://github.com/ministryofjustice/data-platform-support/issues \n\n"
        "Many thanks, Analytical Platform Team."
    )
    sns_client.publish(
        TopicArn=topic_arn,
        Subject="🚨 Analytical Platform Ingestion: Failed Malware Scan Alert",
        Message=message,
    )


def process_unsupported_file(bucket_name, object_key):
    """Process files with unsupported file types."""
    # Email user via SNS
    topic_arn = os.environ.get("NOTIFICATION_TOPIC_ARN")
    message = (
        "This file type is not supported and cannot be scanned. \n\n"
        "This file has NOT been transferred."
        "If you believe this file type is supported please contact us via Support: \n"
        "https://github.com/ministryofjustice/data-platform-support/issues \n\n"
        "Many thanks, Analytical Platform Team."
    )
    sns_client.publish(
        TopicArn=topic_arn,
        Subject="🚨 Analytical Platform Ingestion: Unsupported File Alert",
        Message=message,
    )
