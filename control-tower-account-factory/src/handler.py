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
import copy
import os
import logging
import boto3
from botocore.exceptions import ClientError
from common import BaselineFunction

LOGGER = logging.getLogger()
if 'log_level' in os.environ:
    LOGGER.setLevel(os.environ['log_level'])
else:
    LOGGER.setLevel(logging.INFO)

logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

SESSION = boto3.session.Session()
REGION = SESSION.region_name

class BaselineInit(BaselineFunction):
    """Baseline AWS Control Tower Account"""

    def __init__(self, destimation_account_id, ou_name, region, master_account_id):
        self.account_id = destimation_account_id
        self.ou_name = ou_name
        self.config_file = os.environ['configuration_file']

        # init common functions class
        super().__init__(region, master_account_id)

        # if configuration loaded successfuly, start deployment into new account
        if self._load_config(self.config_file):
            self.__init_deployments()

    def __init_deployments(self):
        """initialize deployment"""
        provision_product = []
        # process defult products common to all ou
        provision_product = self.__get_products_to_provision('default', provision_product)
        # process prducts specific for the OU where the new account was added
        provision_product = self.__get_products_to_provision(self.ou_name, provision_product)
        # start provisioning process
        self._start_provision_product(provision_product, [], self.account_id)

    def __get_products_to_provision(self, organization_unit, provision_product):
        """process products that need to be provision in new account"""
        self._log_info(f'Validating products for ou: {organization_unit}')
        if (organization_unit in self.configuration['organization_units'] and 'products' in self.configuration['organization_units'][organization_unit]):
            for product in self.configuration['organization_units'][organization_unit]['products']:
                if 'product_name' in product and 'provision_name' in product and 'portfolio_name' in product and 'regions' in product:
                    # check if product version provided in configuration
                    product_version = product['product_version'] if 'product_version' in product else None
                    # obtain product id and artifact id
                    product_id, artifact_id, path_id, version = self._get_product_id(product['product_name'], product_version, product['portfolio_name'])
                    if product_id and artifact_id and path_id:
                        if self._update_product_constraint(product_id, product['portfolio_name'], product['regions'], self.account_id):
                            product['id'] = product_id
                            product['artifact'] = artifact_id
                            product['version'] = version
                            product['path'] = path_id
                            product['provision_name'] = f'{self.account_id }-{product["provision_name"]}'
                            provision_product.append(product)
        return provision_product

###############################################################################################################################################

class BaselineAccount(BaselineFunction):
    """Baseline AWS Control Tower Account"""

    def __init__(self, account_id, provision_products, update_products, deployed_products, failed_products, skipped_products, execution_account_id, iteration, max_iterations, region):
        self.destination_account = account_id
        self.execution_account = execution_account_id

        # init common functions class
        super().__init__(region, execution_account_id)

        self.response = {"provision_products": provision_products, "update_products": update_products, "account": account_id, "status": "progress", "deployed_products":deployed_products, "failed_products": failed_products, "skipped_products": skipped_products, "max_iterations": max_iterations, "iteration": iteration}

        # to avoid infinite loop, lambda will stop execution of state machine after define maximum interations
        if iteration >= max_iterations:
            self._log_error(f'Baseline of new account reach max iterations ({max_iterations})')
            self._send_notification('Baseline time out', f'Baseline of new account reach max iterations ({max_iterations})')
            self.response['status'] = 'done'
        else:
            # get list of provision name from products define in configuration
            self.iterate = False
            self.deployment_products_list = []
            self.__get_products_in_scope(provision_products)
            self.__get_products_in_scope(update_products)

            # set connection to tracking table
            self._set_table_connection()

            # start deployment process
            provision_status = self.__baseline_products(provision_products, 'deploy')
            # start update process
            update_status = self.__baseline_products(update_products, 'update')

            if provision_status == 'done' and update_status == 'done':
                self.response['status'] = 'done'
            else:
                self.response['status'] = 'progress'
                # increase iteration if dependency still in progress
                if self.iterate:
                    self.response['iteration'] = iteration + 1

    def __baseline_products(self, products, action):
        """
            go through product configuration
            check deployment dependencies
            start deployment
        """
        status = 'done'


        for product in products:
            # check if product was deployed or failed/skipped deployment
            if product['provision_name'] in self.response['deployed_products'] or product['provision_name'] in self.response['failed_products'] or product['provision_name'] in self.response['skipped_products']:
                if product['provision_name'] in self.response['deployed_products']:
                    # check deployemnt status
                    provision_status = self.__get_provision_status(product['provision_name'])
                    self._log_info(f'Deployemnt Status - Product: {product["provision_name"]} Status: {provision_status}')
                    if provision_status in ['error', 'failed']:
                        self.response['failed_products'].append(product['provision_name'])
                        self.response['deployed_products'].remove(product['provision_name'])
                        self._update_deployment_status(product, 'failed')
                    elif provision_status != 'done':
                        status = 'progress'
                    else:
                        self._update_deployment_status(product, 'done')
                continue

            # if no dependencies, deploy product
            if 'dependson' not in product:
                if self.__process_product(product, action):
                    self.response['deployed_products'].append(product['provision_name'])
                    status = 'progress'
                else:
                    self.response['failed_products'].append(product['provision_name'])
                    status = 'failed'
            else:
                depend_status = 'done'
                for depend_product in product['dependson']:
                    depend_product = f'{self.destination_account}-{depend_product}'
                    self._log_info(f'Checking dependency {depend_product} for product {product["provision_name"]}')
                    if depend_product in self.response['failed_products'] or depend_product in self.response['skipped_products']:
                        self._log_info(f'Status dependency {depend_product} for product {product["provision_name"]}: failed')
                        self.response['skipped_products'].append(product['provision_name'])
                        depend_status = 'failed'
                        break
                    # if dependency on the list but did not start deployment, wait
                    elif depend_product in self.deployment_products_list and depend_product not in self.response['deployed_products']:
                        self._log_info(f'Status dependency {depend_product} for product {product["provision_name"]}: not started')
                        depend_status = 'progress'
                        self.iterate = True
                    # otherwise check dependency deployment status
                    else:
                        provision_status = self.__get_provision_status(depend_product)
                        self._log_info(f'Status dependency {depend_product} for product {product["provision_name"]}: {provision_status}')
                        # if any dependencies failed to deploy, skip product deployment
                        if provision_status in ['error', 'failed']:
                            self.response['failed_products'].append(depend_product)
                            self.response['skipped_products'].append(product['provision_name'])
                            depend_status = 'failed'
                            break
                        elif provision_status != 'done':
                            depend_status = 'progress'

                # if all dependencies deployed successfuly, start product deployment
                if depend_status == 'done':
                    if self.__process_product(product, action):
                        self.response['deployed_products'].append(product['provision_name'])
                        status = 'progress'
                    else:
                        self.response['failed_products'].append(product['provision_name'])

        return status

    def __get_products_in_scope(self, products):
        """
            get list of the provision names that are in the scope of deployment/update
            list will be used by dependency validation to identify if depended product
            need to be updated  or not
        """

        for product in products:
            self.deployment_products_list.append(product['provision_name'])


    def __process_product(self, product, action):
        """deploy or update product"""

        status = False

        # deploy product
        if action == 'deploy':
            status = self.__provision_product(product)

        # update product
        if action == 'update':
            status = self.__update_product(product)

        return status

    def __provision_product(self, product):
        """provision product to new account"""

        self._log_info(f'Provisioning product {product["product_name"]} - Provision Name: {product["provision_name"]}')
        try:
            if 'parameters' in product:
                parameters = self.__process_paramters(product['parameters'])
                self.sc_client.provision_product(
                    ProductId=product['id'],
                    ProvisioningArtifactId=product['artifact'],
                    ProvisionedProductName=product["provision_name"],
                    ProvisioningParameters=parameters,
                    ProvisioningPreferences={
                        'StackSetAccounts': [
                            self.destination_account
                        ],
                        'StackSetRegions': product['regions']
                    }
                )
            else:
                self.sc_client.provision_product(
                    ProductId=product['id'],
                    ProvisioningArtifactId=product['artifact'],
                    ProvisionedProductName=product["provision_name"],
                    ProvisioningPreferences={
                        'StackSetAccounts': [
                            self.destination_account
                        ],
                        'StackSetRegions': product['regions']
                    }
                )
            self._log_info(f'Provision {product["provision_name"]} started')
            self._track_deployment(product, 'deployment', 'in-progress')
            return True
        except ClientError as error:
            self._log_error(f'Error provision product {product["product_name"]}: {error.response["Error"]}')
            self._send_notification('Error provision product', f'Error provision product {product["product_name"]}: {error.response["Error"]}')
            self._track_deployment(product, 'deployment', 'failed')
            return False

    def __update_product(self, product):
        """update product"""

        self._log_info(f'Update product {product["product_name"]} - Provision Name: {product["provision_name"]}')
        try:
            if 'parameters' in product:
                parameters = self.__process_paramters(product['parameters'])

                self.sc_client.update_provisioned_product(
                    ProvisionedProductId=product['provision_id'],
                    ProductId=product['id'],
                    ProvisioningArtifactId=product['artifact'],
                    ProvisioningParameters=parameters,
                    ProvisioningPreferences={
                        'StackSetAccounts': [
                            self.destination_account
                        ],
                        'StackSetRegions': product['regions'],
                        'StackSetOperationType': 'UPDATE'
                    }
                )
            else:
                self.sc_client.update_provisioned_product(
                    ProvisionedProductId=product['provision_id'],
                    ProductId=product['id'],
                    ProvisioningArtifactId=product['artifact'],
                    ProvisioningPreferences={
                        'StackSetAccounts': [
                            self.destination_account
                        ],
                        'StackSetRegions': product['regions'],
                        'StackSetOperationType': 'UPDATE'
                    }
                )
            self._log_info(f'Update {product["provision_name"]} started')
            self._track_deployment(product, 'update', 'in-progress')
            return True
        except ClientError as error:
            self._log_error(f'Error update product {product["product_name"]}: {error.response["Error"]}')
            self._send_notification('Error update product', f'Error provision product {product["product_name"]}: {error.response["Error"]}')
            self._track_deployment(product, 'update', 'failed')
            return False

    def __process_paramters(self, parameters):
        """replace pseudo parameters"""

        parameter_list = []

        for parameter in parameters:
            if 'Key' not in parameter or 'Value' not in parameter:
                continue
            elif '{accountid}' in parameter['Value']:
                parameter['Value'] = parameter['Value'].replace('{accountid}', self.destination_account)
            elif '{masteraccountid}' in parameter['Value']:
                parameter['Value'] = parameter['Value'].replace('{masteraccountid}', self.execution_account)

            parameter_list.append(parameter)

        return parameter_list


    def __get_provision_status(self, provision_name):
        """return status of provisioning product"""

        status = ''

        search_query = f'name:{provision_name}'

        try:
            provision_info = self.sc_client.search_provisioned_products(
                AccessLevelFilter={
                    'Key': 'Account',
                    'Value': 'self'
                },
                Filters={
                    'SearchQuery': [
                        search_query
                    ]
                }
            )

            for provision in provision_info['ProvisionedProducts']:
                if provision['Status'] == 'AVAILABLE':
                    status = 'done'
                elif provision['Status'] in ['ERROR', 'TAINTED']:
                    status = 'failed'
                else:
                    status = 'progress'

        except ClientError as error:
            self._log_error(f'Error obtain provision status for {provision_name}. Error: {error.response["Error"]}')
            self._send_notification('Error obtain provision status', f'Error obtain provision status for {provision_name}. Error: {error.response["Error"]}')
            status = 'error'

        return status


    def get_response(self):
        """return response back to state machine"""

        if self.response["status"] == 'done':
            # send final status
            deployed_products = '\n'.join(self.response["deployed_products"])
            failed_products = '\n'.join(self.response["failed_products"])
            skipped_products = '\n'.join(self.response["skipped_products"])
            message = f'Baseline of account {self.response["account"]} completed. Status:\n\nDeployed products: \n{deployed_products} \n\nFailed products: \n{failed_products} \n\nSkipped products: \n{skipped_products}'
            self._send_notification('Baseline Completed', message)

        return self.response

###############################################################################################################################################

class BaselineUpdate(BaselineFunction):
    """Update AWS Control Tower Account"""

    def __init__(self, region, master_account_id):

        self.state_machine_name = os.environ['state_machine_name']
        self.lambda_role = os.environ['lambda_role']
        self.update_file = os.environ['update_file']

        # init common functions class
        super().__init__(region, master_account_id)

        self.org_client = boto3.client('organizations', region_name=region)

        # if configuration loaded successfuly, start deployment into new account
        if self._load_config(self.update_file):
            self.__init_update()

    def __init_update(self):
        """initialize update"""

        self.account_to_process = []

        # process configuration file
        products_to_provision, products_to_update = self.__process_configuration()

        # iterate through all accounts that need to be updated
        for account in self.account_to_process:
            provision_product = (products_to_provision[account] if account in products_to_provision else [])
            update_product = (products_to_update[account] if account in products_to_update else [])
            # start provision/update products process
            self._start_provision_product(provision_product, update_product, account)


    def __process_configuration(self):
        """process products that need to be provision or update across accounts"""

        self._log_info('Start process update configuration')
        products_to_provision = {}
        products_to_update = {}

        for product in self.configuration['products']:
            if 'product_name' in product and 'portfolio_name' in product and 'provision_name' in product and 'regions' in product and ('accounts' in product or 'organization_units' in product):
                # check if product version provided in configuration
                product_version = product['product_version'] if 'product_version' in product else None
                # obtain product id and artifact id
                product_id, artifact_id, path_id, version = self._get_product_id(product['product_name'], product_version, product['portfolio_name'])
                if product_id and artifact_id and path_id:
                    accounts = (product['accounts'] if 'accounts' in product else None)
                    organization_unit = (product['organization_units'] if 'organization_units' in product else None)
                    # get provisioned names for product
                    provision_name_list = self.__get_product_provision_list(product_id)
                    # get list of accounts where product need to be updated
                    account_list = self.__get_account_list(accounts, organization_unit)
                    for account in account_list:
                        # update product stackset constrain
                        if self._update_product_constraint(product_id, product['portfolio_name'], product['regions'], account):
                            provision_name = f'{account}-{product["provision_name"]}'
                            # make copy of product record
                            deploy_product = copy.deepcopy(product)
                            update_product = copy.deepcopy(product)
                            # if account on the list - update account
                            if provision_name in provision_name_list:
                                stack_set_name = provision_name_list[provision_name]['stack_set_name']
                                regions_list = self.__get_product_deployment_regions(stack_set_name)

                                update_regions = []
                                # check in which regions product was deployed
                                for region in product['regions']:
                                    # initialize new deployment in missin regions
                                    if region not in regions_list:
                                        if 'deployifnotexist' in product and product['deployifnotexist'] == True:
                                            self._log_info(f'Creating new stack instance for: {product["product_name"]} in {account} {region}')
                                            self.__add_stack_instance(stack_set_name, account, region)
                                        else:
                                            self._log_info(f'Skipped deployment for: {product["product_name"]} in {account} {region}')
                                    else:
                                        update_regions.append(region)

                                # for existing regions processd with updates
                                if update_regions:
                                    update_product['id'] = product_id
                                    update_product['artifact'] = artifact_id
                                    update_product['path'] = path_id
                                    update_product['provision_id'] = provision_name_list[provision_name]['id']
                                    update_product['regions'] = update_regions
                                    update_product['account'] = account
                                    update_product['version'] = version
                                    update_product['provision_name'] = provision_name

                                    if account in products_to_update:
                                        products_to_update[account].append(update_product)
                                    else:
                                        products_to_update[account] = [update_product]

                                    if account not in self.account_to_process:
                                        self.account_to_process.append(account)
                            else:
                                if 'deployifnotexist' in product and product['deployifnotexist'] == True:
                                    # if this is new account, new deployment will be created
                                    deploy_product['id'] = product_id
                                    deploy_product['artifact'] = artifact_id
                                    deploy_product['path'] = path_id
                                    deploy_product['account'] = account
                                    deploy_product['version'] = version
                                    deploy_product['provision_name'] = provision_name

                                    if account in products_to_provision:
                                        products_to_provision[account].append(deploy_product)
                                    else:
                                        products_to_provision[account] = [deploy_product]

                                    if account not in self.account_to_process:
                                        self.account_to_process.append(account)
                                else:
                                    self._log_info(f'Skipped deployment for: {product["product_name"]} in {account}')


        return  products_to_provision, products_to_update

    def __add_stack_instance(self, stack_set_name, account, region):
        """create new deployment stack instance """

        try:
            self.cfn_client.create_stack_instances(
                StackSetName=stack_set_name,
                DeploymentTargets={
                    'Accounts': [
                        account
                    ]
                },
                Regions=[
                    region
                ]
            )
            return True
        except ClientError as error:
            self._log_error(f'Error create stack instance. Error: {error.response["Error"]}')
            self._send_notification('Error create stack instance', f'Error: {error.response["Error"]}')
            return False

    def __get_account_list(self, accounts=None, deployment_ou_list=None):
        """get list of the accounts to process"""

        self._log_info('Get accounts list')
        account_list = (accounts if accounts else [])

        if deployment_ou_list:
            try:
                response_roots = self.org_client.list_roots()
                root_ou_id = response_roots['Roots'][0]['Id']
                ou_list = self.__get_ou_ids(root_ou_id)

                for organization_unit in ou_list:
                    if organization_unit not in deployment_ou_list:
                        continue
                    org_id = ou_list[organization_unit]
                    paginator = self.org_client.get_paginator('list_accounts_for_parent')
                    org_iterator = paginator.paginate(
                        ParentId=org_id
                    )
                    for page in org_iterator:
                        for account in page['Accounts']:
                            if account['Id'] not in account_list:
                                account_list.append(account['Id'])
            except ClientError as error:
                self._log_error(f'Error obtain account list. Error: {error.response["Error"]}')
                self._send_notification('Error obtain account list', f'Error: {error.response["Error"]}')

        return account_list

    def __get_ou_ids(self, parent_id):
        """get ids of organization unit"""

        self._log_info('Get organization unit ids')
        ou_list = {}
        try:
            paginator = self.org_client.get_paginator('list_organizational_units_for_parent')
            ou_iterator = paginator.paginate(
                ParentId=parent_id
            )
            for page in ou_iterator:
                for organization_unit in page['OrganizationalUnits']:
                    ou_list[organization_unit['Name']] = organization_unit['Id']
        except ClientError as error:
            self._log_error(f'Error obtain organization unit ids. Error: {error.response["Error"]}')
            self._send_notification('Error obtain organization unit ids', f'Error: {error.response["Error"]}')

        return ou_list

    def __get_product_provision_list(self, product_id):
        """get products provision name list"""

        provision_name_list = {}

        try:
            provision_list = self.sc_client.search_provisioned_products(
                AccessLevelFilter={
                    'Key': 'Account',
                    'Value': 'self'
                },
                Filters={
                    'SearchQuery': [
                        product_id
                    ]
                }
            )

            if 'ProvisionedProducts' in provision_list:
                for provision in provision_list['ProvisionedProducts']:
                    if provision['Type'] == 'CFN_STACKSET' and 'PhysicalId' in provision:
                        provision_id = provision['Id']
                        stack_set_name = ((provision['PhysicalId']).split('/')[1]).split(':')[0]
                        provision_name_list[provision['Name']] = {"id": provision_id, "stack_set_name": stack_set_name}

        except ClientError as error:
            self._log_error(f'Error obtain provision list for product {product_id}. Error: {error.response["Error"]}')
            self._send_notification('Error obtain provision list for product', f'Product: {product_id} Error: {error.response["Error"]}')

        return provision_name_list

    def __get_product_deployment_regions(self, stack_set_name):
        """get regions where product was deployed"""

        regions_list = []

        try:
            paginator = self.cfn_client.get_paginator('list_stack_instances')
            ss_iterator = paginator.paginate(
                StackSetName=stack_set_name
            )

            for page in  ss_iterator:
                for instance in page['Summaries']:
                    if instance['Region'] not in regions_list:
                        regions_list.append(instance['Region'])
        except ClientError as error:
            self._log_error(f'Error obtain list for regions for stack set {stack_set_name}. Error: {error.response["Error"]}')
            self._send_notification('Error obtain regions for stack set', f'Stack Set: {stack_set_name} Error: {error.response["Error"]}')

        return regions_list


###############################################################################################################################################

def lambda_handler(event, context):
    """lambda entry"""
    LOGGER.info(f'REQUEST RECEIVED: {json.dumps(event, default=str)}')

    # get current account
    execution_account_id = context.invoked_function_arn.split(':')[4]

    # check if lambda call by AWS CloudWatch Event in response to creation of new AWS Control Tower account
    if ('detail' in event) and ('eventName' in event['detail']) and (event['detail']['eventName'] == 'CreateManagedAccount'):
        service_detail = event['detail']['serviceEventDetails']
        status = service_detail['createManagedAccountStatus']
        LOGGER.info(
            'AWS Control Tower Event: CreateManagedAccount %s' % (status)
            )
        # get new account id and name
        account_id = status['account']['accountId']
        account_name = status['account']['accountName']
        # get organization unit where the new account was added
        ou_name = status['organizationalUnit']['organizationalUnitName']
        # if account creation completed, start baselien process
        if status['state'] == 'SUCCEEDED':
            LOGGER.info(f'Init Account Baseline. Account name: {account_name}, Account id: {account_id}, OU: {ou_name}')
            BaselineInit(account_id, ou_name, REGION, execution_account_id)
        else:
            LOGGER.info(f'Baseline skipped. Account status: {status["state"]}')
    elif 'Records' in event:
        update_file = os.environ['update_file']
        for record in event['Records']:
            if 's3' in record and record['s3']['object']['key'] == update_file:
                LOGGER.info('Init Update Products')
                BaselineUpdate(REGION, execution_account_id)

    # check if AWS Lambda call by state machine
    elif ('provision_products' in event and 'account' in event):

        deployed_products = (event['deployed_products'] if 'deployed_products' in event else [])
        failed_products = (event['failed_products'] if 'failed_products' in event else [])
        skipped_products = (event['skipped_products'] if 'skipped_products' in event else [])
        max_iterations = (event['max_iterations'] if 'max_iterations' in event and int(event['max_iterations']) > 0 else int(os.environ['max_iterations']))
        # increase how many time lambda was call be state machine
        iteration = (event['iteration'] if 'iteration' in event else 0)

        LOGGER.info(f'Init Product Baseline. Account id: {event["account"]}')
        # start/ contiune account baseline process
        baseline_account = BaselineAccount(event['account'], event['provision_products'], event['update_products'], deployed_products, failed_products, skipped_products, execution_account_id, iteration, max_iterations, REGION)
        # get baseline status
        stm_response = baseline_account.get_response()
        LOGGER.info(f'Response status: {stm_response["status"]}')
        # response status back to state machine
        return stm_response
