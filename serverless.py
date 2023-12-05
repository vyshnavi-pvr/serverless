import json
import requests
import os
import boto3
import base64
from google.cloud import storage
from google.oauth2 import service_account
from botocore.exceptions import ClientError

bucket_name = os.environ.get("BUCKET_NAME")
dynamodb_name = os.environ.get("DYNAMODB_TABLE_NAME")
gcp_secret_name = "gcs_cred"
region_name='us-east-1'

def send_status_message(message_id,from_email, to_email, message):
    
    mailgun_api_key = get_secret("mailgun/api/key", region_name)
    mailgun_api = get_secret("mailgunapi", region_name)

    print(f"send_status_message({message_id},{from_email},{to_email},{message})")
    response = requests.post(
        mailgun_api,
        auth=("api", mailgun_api_key),
        data={"from": from_email,
              "to": [to_email],
              "subject": "Code Release update",
              "text": message})
    #print(f"Mail response {response}")   
    send_dynamodb_message(message_id, message, from_email, to_email)
    
    return response
              
def send_dynamodb_message(id, message, from_email, to_email):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(dynamodb_name)
    item = {
        'id': id,
        'from': from_email,
        'to': to_email,
        'message': message,
       
    }
    # Insert the item
    table.put_item(Item=item)



def upload_to_GCP_bucket(dest_folder, file):
    
    print(f"uploading {file}......")
    # Retrieve the secret
    secret = get_secret(gcp_secret_name, "us-east-1")

    with open('/tmp/secret.json', 'w') as secret_file:

        secret_file.write(secret)

    gcp_service_account_file = json.loads(secret)
    print("secret: ", json.dumps(gcp_service_account_file))

    # Initialize GCP client
    try:
        print("init GCP")
        credentials = service_account.Credentials.from_service_account_file("/tmp/secret.json")
        client = storage.Client(credentials=credentials, project=credentials.project_id)
        print("completed GCP")
    except Exception as e:
        raise e

    file_path = f'{file}'
    filename = os.path.basename(file)
    print(f"File path: {file_path}")
    destination_blob_name = f'{dest_folder}/{filename}'
    
    print(f"File path: {destination_blob_name}")
    # Upload file
    try:
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)
        blob.upload_from_filename(file_path)
        print( "GCS upload complete..")
        return {
            'statusCode': 200,
            'body': json.dumps('File uploaded successfully')
        }
    except Exception as e:
        print (e)

        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def get_secret(secret_name, region_name):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise e
    else:
        # Check if the secret is a string or binary and decode accordingly
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return secret

def release_code(url=None, submission_id=None, local_filename=None, user_release=None, tag=None, from_email=None, to_email=None):
    """
    Downloads a file from an HTTPS URL to a local file.

    Args:
    url (str): URL of the file to download.
    local_filename (str): Path to save the file locally.

    Returns:
    bool: True if download was successful, False otherwise.
    """
    try:
        # Send a GET request to the URL
        response = requests.get(url, stream=True)

        # Check if the request was successful
        if response.status_code == 200:
            # Open the local file for writing in binary mode
            with open(local_filename, 'wb') as f:
                # Write the contents of the response to the file
                for chunk in response.iter_content(chunk_size=128):
                    f.write(chunk)
            directory = '/tmp'

            # List all files in the directory
            files = os.listdir(directory)
            print(f"FILES : {files}")
            send_status_message(submission_id, from_email, to_email, f"Downloading {url} is complete")
            
            upload_to_GCP_bucket(user_release, f"{local_filename}")
            filename = os.path.basename(local_filename)
            send_status_message(submission_id, from_email, to_email, f"Uploaded {filename} to {bucket_name}/{user_release}/{filename}")
            return True
        else:
            send_status_message(submission_id, from_email, to_email, f"Download failed for {url} with submission id {submission_id} by {to_email}")
            print(f"Download failed with status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        send_status_message(submission_id, from_email, to_email, f"Download failed for {url}")
        return False

def lambda_handler(event, context):

    print("Received event: " + json.dumps(event, indent=2))

    # Process each record in the event
    for record in event['Records']:
        sns_message = record['Sns']['Message']
        print("Received message: " + sns_message)

        if 'MessageAttributes' in record['Sns']:
            attributes = record['Sns']['MessageAttributes']
            print("Message Attributes:")
            release_code_file = attributes["release_code_file"]["Value"]
            user_release = attributes["user_release"]["Value"]
            release_tag = attributes["tag"]["Value"]
            from_email = attributes["from_email"]["Value"]
            to_email = attributes["to_email"]["Value"]
            submission_id= attributes["submission_id"]["Value"]

            for key in attributes:
                print(f"{key}: {attributes[key]['Value']}")

            release_code(release_code_file, submission_id, f"/tmp/{release_tag}", user_release,release_tag, from_email, to_email)
            response = send_status_message(submission_id, from_email, to_email, sns_message)
            #print(f"MAIL GUN Response{response}")

        print("Received message attributes: " + json.dumps(attributes, indent=2) )

    return {
        'statusCode': 200,
        'body': json.dumps('Lambda processed successfully')
    }

    return {
        'statusCode': 200,
        'body': json.dumps('Lambda processed successfully')
    }
