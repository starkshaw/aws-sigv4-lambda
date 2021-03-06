# aws-sigv4-lambda
An AWS Lambda function allows you to compose Signature Version 4 signed HTTP requests to AWS services.

## External Dependencies

- [`requests_aws4Auth`](https://github.com/sam-washington/requests-aws4auth)

### How to install external dependencies?

- Creating a function deployment package by following the documentation [here](https://docs.aws.amazon.com/lambda/latest/dg/python-package.html#python-package-dependencies).
- Creating a Lambda layer by following the documentation [here](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path).

## Internal Dependencies

The following libraries are included in AWS Lambda Python runtimes:
- `json`
- `os`
- `logging`

## Example Lambda Event

```
{
  "Endpoint": "https://<api-id>.execute-api.us-east-1.amazonaws.com/<stage>/",
  "HTTPMethod": "GET",
  "Region": "us-east-1",
  "Service": "execute-api",
  "Headers": {
    "Content-Type": "application/json"
  },
  "Body": "{\"message\":\"Test payload.\"}"
}
```

`Headers` and `Body` are optional.

## IAM Permissions

This Lambda function will use the credentials provided by the execution role assigned to the Lambda function to sign the request by default. That means, the IAM role needs to have sufficient permission to invoke relevant APIs.

### Example IAM policy allows function to invoke the root resource of an API via `GET` and `POST` methods:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ExamplePolicy",
      "Effect": "Allow",
      "Action": "execute-api:Invoke",
      "Resource": [
        "arn:aws:execute-api:us-east-1:<account-id>:<api-id>/<stage>/GET/",
        "arn:aws:execute-api:us-east-1:<account-id>:<api-id>/<stage>/POST/"
      ]
    }
  ]
}
```

### Use other credentials

Modifying the following lines in the Lambda function will allow users to use other AWS credentials:

```
auth = AWS4Auth(
  os.environ['AWS_ACCESS_KEY_ID'],
  os.environ['AWS_SECRET_ACCESS_KEY'],
  region,
  service,
  session_token=os.environ['AWS_SESSION_TOKEN']
)
```

## Logging

If the Lambda function has the following permission, it will send diagnostic logs to CloudWatch log:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:<region>:<account-id>:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:<region>:<account-id>:log-group:/aws/lambda/<lambda-function-name>:*"
            ]
        }
    ]
}
```

Lambda function created as of today will automatically generate an execution role with this IAM policy attached.

### Notice

If `INFO` level logging is not required or considered containing sensitive data, it is suggested to remove all `logging.info()` lines or change the logging level from `logger.setLevel(logging.INFO)` to `logger.setLevel(logging.ERROR)`, in which case only error logs will be sent to CloudWatch.