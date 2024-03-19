import os
import boto3
from botocore.exceptions import ClientError

s3_client = boto3.client("s3")
sm_client = boto3.client("secretsmanager")


def handler(event):
    object_key = event["Records"][0]["s3"]["object"]["key"]
    supplier, file_name = object_key.split("/")[:2]
    print(f"Supplier: {supplier}")
    print(f"File name: {file_name}")

    target_bucket_name = sm_client.get_secret_value(
        SecretId=f"ingestion/sftp/{supplier}/target-bucket"
    )["SecretString"]

    copy_source = {"Bucket": os.environ["PROCESSED_BUCKET_NAME"], "Key": object_key}

    try:
        s3_client.copy_object(
            Bucket=target_bucket_name, CopySource=copy_source, Key=object_key
        )
        print(f"Successfully copied {object_key} to {target_bucket_name}")
    except ClientError as e:
        print(f"Error copying object: {e}")
        return

    # attempting to wrap this is try/except failed to delete
    s3_client.delete_object(Bucket=os.environ["PROCESSED_BUCKET_NAME"], Key=object_key)
    print(
        f"Successfully deleted {object_key} from {os.environ['PROCESSED_BUCKET_NAME']}"
    )
    print("handler.py completed successfully!")
