# /*
# * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# *
# * Permission is hereby granted, free of charge, to any person obtaining a copy of this
# * software and associated documentation files (the "Software"), to deal in the Software
# * without restriction, including without limitation the rights to use, copy, modify,
# * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# * permit persons to whom the Software is furnished to do so.
# *
# * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# */

import json
import boto3
import logging
import os
import uuid

log = logging.getLogger()
log.setLevel(logging.INFO)

def deployProduct(config):
    cf = boto3.client('cloudformation')
    cfnUrl = "https://s3.amazonaws.com/"+os.environ['cfnUrl']

    stack_name = "sc-"+(config['Parameters']['ProductName']).replace(" ","-")+"-product-cfn"

    if config['Parameters']['TemplateRuleConstraint']:
        template_const = json.dumps(config['Parameters']['TemplateRuleConstraint'])
    else:
        template_const = ""

    log.info("Deploying product: "+config['Parameters']['ProductName'])
    response = cf.create_stack(
        StackName=stack_name,
        Parameters=[
            {
                'ParameterKey': 'PorfolioStack',
                'ParameterValue': config['Parameters']['PorfolioStack']
            },
            {
                'ParameterKey': 'ProductName',
                'ParameterValue': config['Parameters']['ProductName']
            },
            {
                'ParameterKey': 'ProductDescription',
                'ParameterValue': config['Parameters']['ProductDescription']
            },
            {
                'ParameterKey': 'ProductVersion',
                'ParameterValue': config['Parameters']['ProductVersion']
            },
            {
                'ParameterKey': 'ProductVersionDescription',
                'ParameterValue': config['Parameters']['ProductVersionDescription']
            },
            {
                'ParameterKey': 'ProductTemplateUrl',
                'ParameterValue': 'https://s3.amazonaws.com/'+config['Parameters']['ProductTemplateUrl']
            },
            {
                'ParameterKey': 'ProductRoleName',
                'ParameterValue': config['Parameters']['ProductRoleName']
            },
            {
                'ParameterKey': 'ProductPolicyName',
                'ParameterValue': config['Parameters']['ProductPolicyName']
            },
            {
                'ParameterKey': 'PipelineRoleName',
                'ParameterValue': os.environ['PipelineRole']
            },            
            {
                'ParameterKey': 'ProductRoleTemplateUrl',
                'ParameterValue': 'https://s3.amazonaws.com/'+config['Parameters']['ProductRoleTemplateUrl']
            },
            {
                'ParameterKey': 'TemplateRuleConstraint',
                'ParameterValue': template_const
            },
            {
                'ParameterKey': 'DeploymentBucket',
                'ParameterValue': config['Parameters']['DeploymentBucket']
            },
            {
                'ParameterKey': 'DeployUpdatePipeline',
                'ParameterValue': config['Parameters']['DeployUpdatePipeline']
            },
            {
                'ParameterKey': 'UpdateConfigFileName',
                'ParameterValue': config['Parameters']['UpdateConfigFileName']
            }
        ],
        Capabilities=[ 'CAPABILITY_IAM' , 'CAPABILITY_NAMED_IAM' ],
        EnableTerminationProtection=True,
        TemplateURL=cfnUrl
    )
    log.info(response)

def readConfigFile(s3Bukcet, s3Key):
    s3 = boto3.resource('s3')
    obj = s3.Object(s3Bukcet, s3Key)
    return json.loads(obj.get()['Body'].read().decode('utf-8'))

def lambda_handler(event, context):

    for r in event['Records']:
        s3Key = r['s3']['object']['key']
        s3Bucket = r['s3']['bucket']['name']

        config = readConfigFile(s3Bucket, s3Key)
        deployProduct(config)

    return 'ok'
