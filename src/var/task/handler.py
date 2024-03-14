import os
from datetime import datetime

import boto3

s3_client = boto3.client("s3")
sm_client = boto3.client("secretsmanager")

transfer_time = datetime.now().isoformat()


def handler(event, context):
    print("Received event:", event)
    print("Received context:", context)

    object_key = event["Records"][0]["s3"]["object"]["key"]

    supplier, file_name = object_key.split("/")[:2]
    print(f"Supplier: {supplier}")
    print(f"File name: {file_name}")

    target_bucket_name = sm_client.get_secret_value(
        SecretId=f"ingestion/sftp/{supplier}/target-bucket"
    )["SecretString"]

    # Move the file to the target bucket in another account
    copy_source = {"Bucket": os.environ["PROCESSED_BUCKET_NAME"], "Key": object_key}
    s3_client.copy_object(
        Bucket=target_bucket_name, CopySource=copy_source, Key=object_key
    )
    s3_client.delete_object(
        Bucket=os.environ["PROCESSED_BUCKET_NAME"], Key=object_key
    )
    print("File moved to target and tagged")
