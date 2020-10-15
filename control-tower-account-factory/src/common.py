"""Customizing the AWS Control Tower account factory with AWS Lambda and AWS Service Catalog"""

"""
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

import json
from datetime import datetime
import time
import os
import logging
import yaml
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr

LOGGER = logging.getLogger()
if 'log_level' in os.environ:
    LOGGER.setLevel(os.environ['log_level'])
else:
    LOGGER.setLevel(logging.INFO)

logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

class BaselineFunction():
    """Baseline AWS Control Tower Account"""

    def __init__(self, region, master_account_id):

        self.config_bucket = os.environ['configuration_bucket_name']
        self.lambda_role = os.environ['lambda_role']
        self.state_machine_name = os.environ['state_machine_name']
        self.master_account = master_account_id
        self.sns_topic_arn = None
        self.region = region
        notification_topic = os.environ['notification_topic']
        if notification_topic != 'none':
            self.sns_topic_arn = f'arn:aws:sns:us-east-1:{master_account_id}:{notification_topic}'

        self.s3_client = boto3.client('s3')
        self.sc_client = boto3.client('servicecatalog', region_name=region)
        self.cfn_client = boto3.client('cloudformation', region_name=region)

        self.lambda_portfolio_list = []

    def __get_s3(self, object_name):
        """init boto3 Amazon S3 client"""

        config_content = None

        try:
            s3_response = self.s3_client.get_object(
                Bucket=self.config_bucket,
                Key=object_name
            )

            config_content = s3_response['Body'].read()
        except ClientError as error:
            self._log_error(f'Error load configuration: {error.response["Error"]}')
            self._send_notification('Error load configuration', f'Error: {error.response["Error"]}')

        return config_content

    def _load_config(self, config_file_name):
        """
            get configuration from file from Amazon S3 Bucket.
            Bucket name define under 'configuration_bucket_name' os veriable
            If file has prefix (folder(s)) it has to be define under 'configuration_prefix' os veriable
        """

        # pul config from S3
        config_content = self.__get_s3(config_file_name)
        if config_content:
            self.configuration = yaml.safe_load(config_content)
            return True
        else:
            return False

    def _set_table_connection(self):
        """set boto3 connection to Amazon DynamoDB table"""

        track_table_name = os.environ['track_table']
        dynamodb = boto3.resource('dynamodb', region_name=self.region)
        self.track_table = dynamodb.Table(track_table_name)

    def _track_deployment(self, product, action, status):
        """add record to tracking table"""

        provision_name = product["provision_name"]
        product_name = product["product_name"]
        product_version = product["version"]
        account_id = self.destination_account
        regions = product['regions']
        date = datetime.utcnow().strftime("%Y%m%d%H%M")

        # add deployment track to table
        try:
            self.track_table.put_item(
                Item={
                    'ProvisionName': provision_name,
                    'Date': date,
                    'Product': product_name,
                    'Version': product_version,
                    'Account': account_id,
                    'Regions': regions,
                    'Action': action,
                    'DeploymentStatus': status
                }
            )
        except Exception as error:
            LOGGER.error(f'Error insert deployment record. Error: {str(error)}')

    def _update_deployment_status(self, product, status):
        """update status in tracking table"""

        provision_name = product["provision_name"]

        # update deployment status
        try:
            track_product = self.track_table.scan(
                FilterExpression=Attr('ProvisionName').eq(provision_name) & Attr('DeploymentStatus').eq('in-progress')
            )

            if track_product['Items']:
                track_date = track_product['Items'][0]['Date']

                self.track_table.update_item(
                    Key={
                        'ProvisionName': provision_name,
                        'Date': track_date,
                    },
                    UpdateExpression='SET DeploymentStatus = :val1',
                    ExpressionAttributeValues={
                        ':val1': status
                    }
                )

        except Exception as error:
            LOGGER.error(f'Error update deployment status. Error: {str(error)}')

    def _send_notification(self, subject, message):
        """send SNS notification"""

        if self.sns_topic_arn:
            try:
                sns_client = boto3.client('sns')
                sns_client.publish(
                    TopicArn=self.sns_topic_arn,
                    Message=message,
                    Subject=subject
                )
            except ClientError as error:
                LOGGER.error(f'Error send notification. Subject {subject}. Message: {message}, Error: {error.response["Error"]}')

    def _get_product_id(self, product_name, product_version, portfolio_name):
        """Return product id , artifact id and path id for porvided product and porfolio name"""

        product_id = None
        artifact_id = None
        path_id = None
        version = None

        # add lamda role to portfolio
        if not self.__add_lambda_to_portfolio_principal(portfolio_name):
            return product_id, artifact_id, path_id

        self._log_info(f'Searching product name: {product_name}')

        try:

            sc_response = self.sc_client.search_products_as_admin(
                SortBy='Title',
                SortOrder='ASCENDING',
                ProductSource='ACCOUNT',
                Filters={
                    'FullTextSearch': [
                        product_name
                    ]
                }
            )

            product_list = []
            #Iterate through all return products
            for product in sc_response['ProductViewDetails']:
                # find product
                if product_name in product['ProductViewSummary']['Name']:
                    product_list.append({'ProductId': product['ProductViewSummary']['ProductId'], 'CreatedTime': product['CreatedTime']})

            # if product found
            if product_list:
                # if more the on product get the latest one based on the date/time
                last_product_id = max(product_list, key=lambda item: item['CreatedTime'])
                product_id = last_product_id['ProductId']

                # search artifacts (versions) of product
                product_artifacts = self.sc_client.list_provisioning_artifacts(
                    AcceptLanguage='en',
                    ProductId=product_id
                )

                if product_version:
                    version = product_version
                    for artifact in product_artifacts['ProvisioningArtifactDetails']:
                        # find product that match provided version
                        if artifact['Name'] == product_version:
                            artifact_id = artifact['Id']
                else:
                    # get last product version by creation date
                    last_artifact_id = max(product_artifacts['ProvisioningArtifactDetails'], key=lambda item: item['CreatedTime'])
                    artifact_id = last_artifact_id['Id']
                    version = last_artifact_id['Name']

                # get product launch path id
                launch_paths_list = self.sc_client.list_launch_paths(
                    ProductId=product_id
                )
                for launch_path in launch_paths_list['LaunchPathSummaries']:
                    if launch_path['Name'] == portfolio_name:
                        path_id = launch_path['Id']

        except ClientError as error:
            self._log_error(f'Error obtain id for product: {product_name}. Error: {error.response["Error"]}')
            self._send_notification('Error obtain product id', f'Product name: {product_name}. Error: {error.response["Error"]}')

        return product_id, artifact_id, path_id, version

    def __add_lambda_to_portfolio_principal(self, portfolio_name):
        """Add AWS Lambda IAM role to portfolio in order for Lambda function to provision products"""

        # check if lambda already added to portfolio
        if portfolio_name in self.lambda_portfolio_list:
            return True

        portfolio_id = None
        has_lambda_principal = False

        try:
            portfolio_list = self.sc_client.list_portfolios()

            # get id for provided portfolio name
            for porfolio in portfolio_list['PortfolioDetails']:
                if porfolio['DisplayName'] == portfolio_name:
                    portfolio_id = porfolio['Id']

            # if portfolio exists and Lambda IAM role does not have access to porfolio, add it
            if portfolio_id:
                portfolio_principals = self.sc_client.list_principals_for_portfolio(
                    PortfolioId=portfolio_id
                )
                for principal in portfolio_principals['Principals']:
                    if principal['PrincipalARN'] == self.lambda_role:
                        has_lambda_principal = True
                        self.lambda_portfolio_list.append(portfolio_name)
                        break

                if not has_lambda_principal:
                    self.sc_client.associate_principal_with_portfolio(
                        PortfolioId=portfolio_id,
                        PrincipalARN=self.lambda_role,
                        PrincipalType='IAM'
                    )
                    self.lambda_portfolio_list.append(portfolio_name)
                    time.sleep(30)
                    self._log_info(f'Lambda role added to portfolio {portfolio_name}')

                return True
            else:
                return False
        except ClientError as error:
            self._log_error(f'Error adding lambda role to portfolio : {portfolio_name}. Error: {error.response["Error"]}')
            self._send_notification('Error adding lambda role to portfolio', f'Portfolio name: {portfolio_name}. Error: {error.response["Error"]}')
            return False

    def __get_product_portfolio(self, product_id, portfolio_name):
        """Return portfolio id for porvided product id and porfolio name"""

        portfolio_id = None

        try:

            portfolio_list = self.sc_client.list_portfolios_for_product(
                ProductId=product_id
            )

            for portfolio in portfolio_list['PortfolioDetails']:
                if portfolio['DisplayName'] == portfolio_name:
                    portfolio_id = portfolio['Id']
                    break

        except ClientError as error:
            self._log_error(f'Error getting portfolio id for portfolio name: {portfolio_name} and product: {product_id}. Error: {error.response["Error"]}')
            self._send_notification('Error obtain portfolio id', f'Portfolio name: {portfolio_name}, product id: {product_id}. Error: {error.response["Error"]}')

        return portfolio_id

    def _update_product_constraint(self, product_id, porfolio_name, regions, destination_account):
        """Delete Launch contraint, if exists. Add/update StackSet contraint for product"""

        # get porfolio id
        porfolio_id = self.__get_product_portfolio(product_id, porfolio_name)

        if not porfolio_id:
            self._log_error(f'Portfolio id for product {product_id} could not be determined. Product deployment skipped')
            self._send_notification('Portfolio issue', f'Portfolio id for product {product_id} could not be determined. Product deployment skipped')
            return False

        try:
            # get list of constraints associate with product
            constraint_list = self.sc_client.list_constraints_for_portfolio(
                PortfolioId=porfolio_id,
                ProductId=product_id
            )

            stack_set_constraint_id = None

            # iterate through constraints
            for constraint in  constraint_list['ConstraintDetails']:
                # if product has Launch constraint, it has to be deleted as
                # Service Catalog does not allow both Launch and StackSet contraints
                # attach to product
                if constraint['Type'] == 'LAUNCH':
                    self._log_info(f'Deleting LAUNCH contraint id: {constraint["ConstraintId"]}')
                    self.sc_client.delete_constraint(Id=constraint['ConstraintId'])
                elif constraint['Type'] == 'STACKSET':
                    stack_set_constraint_id = constraint['ConstraintId']
            # if no StackSet constraint create one
            if not stack_set_constraint_id:
                admin_role = f'arn:aws:iam::{self.master_account}:role/service-role/AWSControlTowerStackSetRole'
                constraint_config = {"Version": "2.0", "Properties": {"AccountList": [destination_account], "RegionList": regions, "AdminRole": admin_role, "ExecutionRole": "AWSControlTowerExecution"}}

                self.sc_client.create_constraint(
                    PortfolioId=porfolio_id,
                    ProductId=product_id,
                    Parameters=json.dumps(constraint_config),
                    Type='STACKSET',
                    Description='Control-Tower-Account-Baseline',
                    IdempotencyToken=f'ct-baseline-constraint-{datetime.utcnow().strftime("%Y%m%d%H%M%S%f")}'
                )
            # if product has StackSet constraint add the new account and region, if needed
            else:
                constraint_info = self.sc_client.describe_constraint(
                    Id=stack_set_constraint_id
                )

                constraint_config = json.loads(constraint_info['ConstraintParameters'])

                if destination_account not in constraint_config['Properties']['AccountList']:
                    (constraint_config['Properties']['AccountList']).append(destination_account)

                for region in regions:
                    if region not in constraint_config['Properties']['RegionList']:
                        (constraint_config['Properties']['RegionList']).append(region)

                self.sc_client.update_constraint(
                    Id=stack_set_constraint_id,
                    Parameters=json.dumps(constraint_config)
                )

            return True
        except ClientError as error:
            self._log_error(f'Error adding account to contraint: Error: {error.response["Error"]}')
            self._send_notification('Error adding account to contraint', f'Error: {error.response["Error"]}')
            return False

    def _start_provision_product(self, provision_product, update_product, destination_account):
        """Call AWS Step Function State Machine"""

        if not provision_product and not update_product:
            self._log_info('Nothing to process')
            return None

        # create execute name
        sfn_execution_name = f'control-tower-account-factory-execution-{destination_account}-{datetime.utcnow().strftime("%Y%m%d%H%M%S%F")}'
        self._log_info('Starting AWS Step Function for Products')

        max_iterations = (self.configuration['max_iterations'] if 'max_iterations' in self.configuration else 0)
        # format input
        sfn_input = json.dumps({"provision_products": provision_product, "update_products": update_product, "account": destination_account, "status": "init", "deployed_products":[], "failed_products": [], "skipped_products": [], "max_iterations": max_iterations, "iteration": 0})
        self._log_info(f'SFN inout: {sfn_input}')

        try:
            sfn_client = boto3.client('stepfunctions')

            # call SFN
            sfn_client.start_execution(
                stateMachineArn=f'arn:aws:states:us-east-1:620936997165:stateMachine:{self.state_machine_name}',
                name=sfn_execution_name,
                input=sfn_input
            )
        except ClientError as error:
            self._log_error(f'Error start step function. Execution name: {sfn_execution_name}. Error: {error.response["Error"]}')
            self._send_notification('Error start step function', f'Execution name: {sfn_execution_name}. Error: {error.response["Error"]}')

    def _log_error(self, message):
        LOGGER.error(message)

    def _log_info(self, message):
        LOGGER.info(message)
