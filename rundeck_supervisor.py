#!/usr/bin/python3
import urllib.request
import urllib.error
import json
import requests
import boto3
import base64
from botocore.exceptions import ClientError
from datetime import datetime
import pytz
import dateutil.parser
import inspect


def get_secret(secret_name, region_name, key):

    session = boto3.session.Session()
    client = session.client(
        service_name = 'secretsmanager',
        region_name = region_name
    )

    try:

        get_secret_value_response = client.get_secret_value(
            SecretId = secret_name
        )

    except ClientError as e:

        raise e

    else:

        if 'SecretString' in get_secret_value_response:

            secret = get_secret_value_response['SecretString']
            return json.loads(secret)[key]

        else:

            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret


def upd_secret(secret_name, region_name, key, val):

    session = boto3.session.Session()
    try:

        client = session.client(
            service_name = 'secretsmanager',
            region_name = region_name
        )

    except Exception as error:

        print('\nLine number: %s\nAction: %s\nError: %s\n' % (inspect.stack()[0][2], inspect.stack()[0][3], error))
        raise error

    else:

        try:

            response = client.update_secret(
                SecretId = '%s' % (secret_name),
                SecretString = '{"%s":"%s"}' % (key, val),
            )

        except Exception as error:

            print('\nLine number: %s\nAction: %s\nError: %s\n' % (inspect.stack()[0][2], inspect.stack()[0][3], error))
            raise error

        else:

            return 0


# Thanks Rommel for this code snippet - AlertManager API request
def report_status(module="", job="", status="", details="", severity="INFO", permalink=""):

    message = [{
        'labels': {
            'alertname': 'Rundeck - Job failure',
            'module': module,
            'job': job,
            'severity': severity
        },
        'annotations': {
            'description': details,
            'summary': 'The %s/%s job finished with %s status.' % (module, job, status)
        },
        'GeneratorURL': permalink
    }]

    url = 'https://alertmanager.greenmile.com/api/v1/alerts'
    body = json.dumps(message)
    body = body.encode()
    #print(body)
    req = urllib.request.Request(url, body)
    req.add_header('Content-Type', 'application/json')

    try:

        urllib.request.urlopen(req)

    except urllib.error.HTTPError as e:

        print('Failed to send the SNS message below:\n%s' % message)
        response = json.load(e)

        if 'description' in response:

            print(response['description'])

        raise e


class Session:

    token = ''
    headers = ''
    user = ''
    srv_addr = ''
    utc = ''

    def __init__(self):

        self.utc = pytz.UTC
        self.srv_addr = 'https://rundeck.greenmile.com'
        self.user = 'rundeck'
        self.key = 'rundeck_token'
        self.secret_name = 'rundeck_token'
        self.region = 'us-east-1'

        try:

            self.token = get_secret(self.secret_name, self.region, self.key)
            self.headers = {
                'Accept': 'application/json',
                'X-Rundeck-Auth-Token': self.token,
            }

        except Exception as error:

            print('\nLine number: %s\nAction: %s\nError: %s\n' % (inspect.stack()[0][2], inspect.stack()[0][3], error))
            raise error

        else:

            self.chk_token()

    def upd_token(self, key, val):

        return upd_secret(self.secret_name, self.region, key, val)

    def get_token(self):

        return self.token

    def chk_token(self):

        days_limit = 5
        call = 'api/21/tokens'
        response = requests.get('%s/%s/%s' % (self.srv_addr, call, self.user), headers=self.headers)
        dict = response.json()

        for index in dict:

            if ( (dateutil.parser.parse(index['expiration']) - self.utc.localize(datetime.now())).days >= days_limit ):
                return 'valid'

            else:

                self.token = self.add_token()
                self.del_token(self.token, index['id'])
                return 'updated'

    def add_token(self):

        call = 'api/21/tokens'
        body = {
            'Accept': 'application/json',
            'X-Rundeck-Auth-Token': self.token,
            'Content-Type': 'application/json',
        }
        data = '{\n  "roles": "*",\n  "duration": "5d"\n}'

        response = requests.post('%s/%s/%s' % (self.srv_addr, call, self.user), headers=body, data=data)
        dict = response.json()
        self.upd_token('rundeck_token', dict['token'])

        return dict['token']

    def del_token(self, new_token, last_token_id):

        call = 'api/21/token'
        body = {
            'Accept': 'application/json',
            'X-Rundeck-Auth-Token': new_token,
            'Content-Type': 'application/json',
        }

        response = requests.delete('%s/%s/%s' % (self.srv_addr, call, last_token_id), headers=body)
        return response

    def chk_job(self):

        days_limit = 2
        call = 'api/21/projects'
        body = {
            'Accept': 'application/json',
            'X-Rundeck-Auth-Token': self.token,
            'Content-Type': 'application/json',
        }

        response = requests.get('%s/%s' % (self.srv_addr, call), headers=body, timeout=120)
        dict = response.json()

        for project in dict:

            job_dict = self.get_job(project['name'])

            for job in job_dict:

                exec_list = self.get_job_info(job['id'])

                first_execution = exec_list['executions'][0]
                if ( first_execution['status'] != 'succeeded'
                        and ((self.utc.localize(datetime.now()) -
                              dateutil.parser.parse(first_execution['date-started']['date'])).days < days_limit)):

                    details = "Failed after %ss at %s UTC started at %s UTC by %s" % \
                              (first_execution['job']['averageDuration'] / 1000.0,
                               (dateutil.parser.parse(first_execution['date-ended']['date'])).strftime("%a %H:%M %p"),
                               (dateutil.parser.parse(first_execution['date-started']['date'])).strftime("%a %H:%M %p"),
                               first_execution['user'])
                    try:

                        report_status(project['name'], job['name'], first_execution['status'], details,
                                  "INFO", first_execution['permalink'])

                    except Exception as error:

                        print('\nLine number: %s\nAction: %s\nError: %s\n' % (inspect.stack()[0][2],
                                                                              inspect.stack()[0][3], error))
                        raise error

    def get_job(self, project):

        call = 'api/21/project/%s/jobs' % (project)
        body = {
            'Accept': 'application/json',
            'X-Rundeck-Auth-Token': self.token,
            'Content-Type': 'application/json',
        }
        data = '{\n  "scheduleEnabled": "true",\n  "enabled": "true"\n}'

        response = requests.get('%s/%s' % (self.srv_addr, call), headers=body, data=data)
        return response.json()

    def get_job_info(self, job_id):

        call = 'api/21/job/%s/executions' % (job_id)
        body = {
            'Accept': 'application/json',
            'X-Rundeck-Auth-Token': self.token,
            'Content-Type': 'application/json',
        }

        response = requests.get('%s/%s' % (self.srv_addr, call), headers=body)
        return response.json()


try:

    rundeck = Session()

except Exception as error:

    print('\nLine number: %s\nAction: %s\nError: %s\n' % (inspect.stack()[0][2], inspect.stack()[0][3], error))
    exit(1)

else:

    try:

        rundeck.chk_job()

    except Exception as error:

        print('\nLine number: %s\nAction: %s\nError: %s\n' % (inspect.stack()[0][2], inspect.stack()[0][3], error))
        exit(1)

    else:

        exit(0)
