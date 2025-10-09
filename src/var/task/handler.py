import os
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

s3_client = boto3.client("s3")
sm_client = boto3.client("secretsmanager")
sns_client = boto3.client("sns")
timestamp = datetime.now().isoformat()
timestamp_epoch = int(datetime.now().timestamp())


def handler(event, context):  # pylint: disable=unused-argument
    object_key = event["Records"][0]["s3"]["object"]["key"]
    supplier, uploaded_object = object_key.split("/", 1)
    print(f"Supplier: {supplier}")
    print(f"Object: {uploaded_object}")

    if "/" in uploaded_object:
        file_name = uploaded_object.split("/")[-1]
    else:
        file_name = uploaded_object

    target_bucket = sm_client.get_secret_value(
        SecretId=f"ingestion/sftp/{supplier}/target-bucket"
    )["SecretString"]

    if "/" in target_bucket:
        target_bucket, bucket_prefix = target_bucket.split("/", 1)
        destination_object_key = f"{bucket_prefix}/{uploaded_object}"
    else:
        destination_object_key = object_key

    if supplier in ["essex-police"]:
        destination_object_key = (
            f"{bucket_prefix}/file_land_timestamp={timestamp_epoch}/{file_name}"
        )

    copy_source = {"Bucket": os.environ["PROCESSED_BUCKET_NAME"], "Key": object_key}

    try:
        s3_client.copy_object(
            Bucket=target_bucket,
            CopySource=copy_source,
            Key=destination_object_key,
            ACL="bucket-owner-full-control",
        )
        print(
            f"Successfully copied {object_key} to {target_bucket}/{destination_object_key}"
        )
        sns_client.publish(
            TopicArn=os.environ["SNS_TOPIC_ARN"],
            Message=f"transferred,{supplier}/{destination_object_key},{timestamp}",
        )

    except ClientError as e:
        print(f"Error copying object: {e}")
        return

    # attempting to wrap this is try/except failed to delete
    s3_client.delete_object(Bucket=os.environ["PROCESSED_BUCKET_NAME"], Key=object_key)
    print(
        f"Successfully deleted {object_key} from {os.environ['PROCESSED_BUCKET_NAME']}"
    )
    print("handler.py completed successfully!")
