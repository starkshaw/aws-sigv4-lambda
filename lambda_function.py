import json
import logging
import requests
import os
from requests_aws4auth import AWS4Auth
logger = logging.getLogger()
logger.setLevel(logging.INFO)
supported_http_methods = ['GET', 'POST', 'PUT',
                          'DELETE', 'OPTIONS', 'HEAD', 'PATCH']


def lambda_handler(event, context):
    logger.info('Event: {}'.format(json.dumps(event)))
    try:
        if not 'Endpoint' in event or len(event['Endpoint']) == 0:
            raise Exception('\'Endpoint\' parameter cannot be empty.')
        else:
            endpoint = event['Endpoint']
        if not 'HTTPMethod' in event or len(event['HTTPMethod']) == 0:
            raise Exception('\'HTTPMethod\' parameter cannot be empty.')
        else:
            http_method = event['HTTPMethod'].upper()
        if not http_method in supported_http_methods:
            raise Exception(
                '\'{}\' is not a supported HTTP method.'.format(http_method))
        if not 'Region' in event or len(event['Region']) == 0:
            raise Exception('\'Region\' parameter cannot be empty.')
        else:
            region = event['Region']
        if not 'Service' in event or len(event['Service']) == 0:
            raise Exception('\'Service\' parameter cannot be empty.')
        else:
            service = event['Service']
    except Exception as e:
        logger.error('Error: {}'.format(e))
        error_msg = {
            'message': str(e)
        }
        return {
            'statusCode': 502,
            'body': json.dumps(error_msg)
        }
    auth = AWS4Auth(
        os.environ['AWS_ACCESS_KEY_ID'],
        os.environ['AWS_SECRET_ACCESS_KEY'],
        region,
        service,
        session_token=os.environ['AWS_SESSION_TOKEN']
    )
    if http_method == 'GET':
        logger.info('GET {}'.format(endpoint))
        response = requests.get(
            endpoint,
            auth=auth,
            data=event['Body'] if 'Body' in event and isinstance(
                event['Body'], str) and len(event['Body']) > 0 else None,
            headers=event['Headers'] if isinstance(
                event['Headers'], dict) else None
        )
        for i in response.request.headers:
            logger.info('{}: {}'.format(i, response.request.headers[i]))
    elif http_method == 'POST':
        logger.info('POST {}'.format(endpoint))
        response = requests.post(
            endpoint,
            auth=auth,
            data=event['Body'] if 'Body' in event and isinstance(
                event['Body'], str) and len(event['Body']) > 0 else None,
            headers=event['Headers'] if isinstance(
                event['Headers'], dict) else None
        )
        for i in response.request.headers:
            logger.info('{}: {}'.format(i, response.request.headers[i]))
    elif http_method == 'PUT':
        logger.info('PUT {}'.format(endpoint))
        response = requests.put(
            endpoint,
            auth=auth,
            data=event['Body'] if 'Body' in event and isinstance(
                event['Body'], str) and len(event['Body']) > 0 else None,
            headers=event['Headers'] if isinstance(
                event['Headers'], dict) else None
        )
        for i in response.request.headers:
            logger.info('{}: {}'.format(i, response.request.headers[i]))
    elif http_method == 'DELETE':
        logger.info('DELETE {}'.format(endpoint))
        response = requests.delete(
            endpoint,
            auth=auth,
            data=event['Body'] if 'Body' in event and isinstance(
                event['Body'], str) and len(event['Body']) > 0 else None,
            headers=event['Headers'] if isinstance(
                event['Headers'], dict) else None
        )
        for i in response.request.headers:
            logger.info('{}: {}'.format(i, response.request.headers[i]))
    elif http_method == 'OPTIONS':
        logger.info('OPTIONS {}'.format(endpoint))
        response = requests.options(
            endpoint,
            auth=auth,
            data=event['Body'] if 'Body' in event and isinstance(
                event['Body'], str) and len(event['Body']) > 0 else None,
            headers=event['Headers'] if isinstance(
                event['Headers'], dict) else None
        )
        for i in response.request.headers:
            logger.info('{}: {}'.format(i, response.request.headers[i]))
    elif http_method == 'HEAD':
        logger.info('HEAD {}'.format(endpoint))
        response = requests.head(
            endpoint,
            auth=auth,
            data=event['Body'] if 'Body' in event and isinstance(
                event['Body'], str) and len(event['Body']) > 0 else None,
            headers=event['Headers'] if isinstance(
                event['Headers'], dict) else None
        )
        for i in response.request.headers:
            logger.info('{}: {}'.format(i, response.request.headers[i]))
    elif http_method == 'PATCH':
        logger.info('PATCH {}'.format(endpoint))
        response = requests.patch(
            endpoint,
            auth=auth,
            data=event['Body'] if 'Body' in event and isinstance(
                event['Body'], str) and len(event['Body']) > 0 else None,
            headers=event['Headers'] if isinstance(
                event['Headers'], dict) else None
        )
        for i in response.request.headers:
            logger.info('{}: {}'.format(i, response.request.headers[i]))
    logger.info('Response status code: {}'.format(response.status_code))
    logger.info('Response body: {}'.format(response.text))
    if isinstance(response, requests.models.Response):
        return {
            'statusCode': response.status_code,
            'body': response.text,
            'headers': dict(response.headers)
        }
    else:
        return {
            'statusCode': 200,
            'body': 'The request is successfully sent but the response is empty.'
        }
