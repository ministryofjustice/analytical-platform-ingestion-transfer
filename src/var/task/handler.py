import json
import logging
import os
from datetime import datetime

import boto3
from notifications_python_client.notifications import NotificationsAPIClient

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Setup clients
s3_client = boto3.client("s3")
sm_client = boto3.client("secretsmanager")
sts_client = boto3.client('sts')

# Setup GOV UK Notify client
govuk_notify_api_key_secret = os.environ["GOVUK_NOTIFY_API_KEY_SECRET"]
govuk_notify_api_key = sm_client.get_secret_value(SecretId=govuk_notify_api_key_secret)[
    "SecretString"
]
govuk_notify_templates_secret = os.environ["GOVUK_NOTIFY_TEMPLATES_SECRET"]
govuk_notify_templates = json.loads(
    sm_client.get_secret_value(SecretId=govuk_notify_templates_secret)["SecretString"]
)
notifications_client = NotificationsAPIClient(govuk_notify_api_key)

# Setup Timestamps
timestamp = datetime.now().isoformat()
timestamp_epoch = int(datetime.now().timestamp())


def supplier_configuration(supplier):
    data_contact = sm_client.get_secret_value(
        SecretId=f"transfer/sftp/{supplier}/data-contact"
    )["SecretString"]

    technical_contact = sm_client.get_secret_value(
        SecretId=f"transfer/sftp/{supplier}/technical-contact"
    )["SecretString"]

    target_bucket = sm_client.get_secret_value(
        SecretId=f"transfer/sftp/{supplier}/target-bucket"
    )["SecretString"]

    return {
        "data_contact": data_contact,
        "technical_contact": technical_contact,
        "target_bucket": target_bucket,
    }


def send_gov_uk_notify(template, email_address, personalisation):
    response = notifications_client.send_email_notification(
        template_id=template,
        email_address=email_address,
        personalisation=personalisation,
    )
    return response


def handler(event, context):  # pylint: disable=unused-argument
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
        detail = event.get("detail", {})
        scan_status = detail.get("scanStatus")
        scan_result_details = detail.get("scanResultDetails", {})
        scan_result_status = scan_result_details.get("scanResultStatus")

        # Extract S3 object details
        s3_object_details = detail.get("s3ObjectDetails", {})
        bucket_name = s3_object_details.get("bucketName")
        object_key = s3_object_details.get("objectKey")

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
            if scan_result_status == "NO_THREATS_FOUND":
                process_no_threats_found_file(bucket_name, object_key)
                return {
                    "statusCode": 200,
                    "body": json.dumps(
                        f"Successfully processed - NO THREATS FOUND in file: {object_key} in bucket: {bucket_name}"
                    ),
                }
            elif scan_result_status == "THREATS_FOUND":
                threats = scan_result_details.get("threats", [])
                process_threats_found_file(bucket_name, object_key, threats)
                return {
                    "statusCode": 200,
                    "body": json.dumps(
                        f"Successfully processed - THREATS FOUND in file: {object_key} in bucket: {bucket_name}"
                    ),
                }
            else:
                logger.warning(f"Unknown scan result status: {scan_result_status}")
        elif scan_status == "SKIPPED":
            if scan_result_status == "ACCESS_DENIED":
                process_access_denied(object_key)
                return {
                    "statusCode": 403,
                    "body": json.dumps(
                        f"Error: Access denied to file '{object_key}' in '{bucket_name}'."
                    ),
                }
            if scan_result_status == "UNSUPPORTED":
                process_unsupported_file(object_key)
                return {
                    "statusCode": 415,
                    "body": json.dumps(
                        f"Error: File type is unsupported. Filename: '{object_key}'"
                    ),
                }
        elif scan_status == "FAILED":
            process_failed_scan(object_key)
            return {
                "statusCode": 500,
                "body": json.dumps(f"Error: Scan failed on file '{object_key}'."),
            }
        else:
            logger.warning(f"Unknown scan status: {scan_status}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                f"Successfully processed scan status: {scan_status}, result: {scan_result_status}"
            ),
        }

    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps(f"Error processing event: {str(e)}"),
        }

def process_no_threats_found_file(bucket_name, object_key):

    logger.info(
        f"Processing NO_THREATS_FOUND file: {object_key} in bucket: {bucket_name}"
    )

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

    logger.info(
        f"Processing THREATS_FOUND - file: '{object_key}' in bucket '{bucket_name}'"
    )
    logger.info(f"Detected threats: {json.dumps(threats)}")

    # Move file to Quarantine bucket, and then delete file.
    quarantine_bucket = os.environ.get("QUARANTINE_BUCKET_NAME")
    s3_client.copy_object(
        CopySource={"Bucket": bucket_name, "Key": object_key},
        Bucket=quarantine_bucket,
        Key=object_key,
    )
    s3_client.delete_object(Bucket=bucket_name, Key=object_key)

    # TODO: Send a GOV UK NOTIFY email here


def process_access_denied(object_key):

    # TODO: Send a GOV UK NOTIFY email here


def process_failed_scan(object_key):

    # TODO: Send a GOV UK NOTIFY email here


def process_unsupported_file(object_key):

    # Extract supplier from the object_key
    if "/" in object_key:
        supplier, remaining_path = object_key.split("/", 1)
        filename = os.path.basename(remaining_path)
    else:
        supplier = "unknown"

    # Fetch supplier configuration
    supplier_config = supplier_configuration(supplier)

    # GOV.UK Notify Technical Contact
    send_gov_uk_notify(
        template=govuk_notify_templates[
            "transfer_services_unsupported"
        ],
        email_address=supplier_config["technical_contact"],
        personalisation={
            "filename": filename,
            "supplier": supplier,
        },
    )
