# serverless
lambda function for web application to save in gcp bucket

Lambda Function
- The Lambda function will be invoked by the SNS notification.
- Downloads the release from the GitHub repository and stores it in Google Cloud Storage Bucket.
- Emails the user the about the status of download.
- Track the emails sent in DynamoDB of te message.
