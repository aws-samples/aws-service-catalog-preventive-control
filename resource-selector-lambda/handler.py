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
import botocore
import logging
import random
from botocore.vendored import requests
import re

# setup simple logging for INFO
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Constants
# Get current region region
session = boto3.session.Session()
region = session.region_name


#Class to search resources based on the specified criteria
class ResourceSelector(object):
    def __init__(self, **kwargs):
        cfg = kwargs['cfg']
        resource = kwargs['resource']

        # Get current Region
        self.region = kwargs['region']

        # What to do with CFN stack if resource not found - either failed or let cfn run
        self.error = (cfg['Options']['Error'] if 'Options' in cfg and 'Error' in cfg['Options']
                             else 'failed')
        # How many items return when more the one found (all, single)
        self.output = (cfg['Options']['Output'] if 'Options' in cfg and 'Output' in cfg['Options']
                             else 'all')
        # When more the one tag provided should resource match on all tags or any tag
        self.match = (cfg['Options']['Match'] if 'Options' in cfg and 'Match' in cfg['Options']
                             else 'any')
        # Return subnets that have at least X available IPs
        self.availableIp = (int(cfg['Options']['AvailableIP']) if 'Options' in cfg and 'AvailableIP' in cfg['Options']
                             else 5)
        # IAM group name
        self.groupName = (cfg['Options']['GroupName'] if 'Options' in cfg and 'GroupName' in cfg['Options']
                             else None)
        # ACM Certificate Domain name
        self.domain = (cfg['Options']['Domain'] if 'Options' in cfg and 'Domain' in cfg['Options']
                             else None)
        # KMS alias to search
        self.kmsAlias = (cfg['Options']['KMSAlias'] if 'Options' in cfg and 'KMSAlias' in cfg['Options']
                             else None)
        # In what format return key: as alias or as id
        self.kmsOutput = (cfg['Options']['KMSOutput'] if 'Options' in cfg and 'KMSOutput' in cfg['Options']
                             else 'id')
        # IAM Policy name
        self.policyName = (cfg['Options']['PolicyName'] if 'Options' in cfg and 'PolicyName' in cfg['Options']
                             else None)
        # IAM Role name
        self.roleName = (cfg['Options']['RoleName'] if 'Options' in cfg and 'RoleName' in cfg['Options']
                             else None)
        # IAM Role path
        self.rolePath = (cfg['Options']['RolePath'] if 'Options' in cfg and 'RolePath' in cfg['Options']
                             else '/')

        # Get VPC(s) for subnets or security group
        vpcs = (kwargs['vpc'] if 'vpc' in kwargs else None)

        # Search resources
        if resource == 'vpc':
            self.getVPCs(cfg)

        if resource == 'subnet':
            vpcList = self.convert_vps_to_list(vpcs)
            self.getSubnets(cfg, vpcList)

        if resource == 'sg':
            vpcList = self.convert_vps_to_list(vpcs)
            self.getSecurityGroup(cfg, vpcList)

        if resource == 'acm':
            self.getACM(cfg)

        if resource == 'kms':
            self.getKMS()

        if resource == 'policy':
            self.getPolicy()

        if resource == 'role':
            self.getRoles(cfg)

    # output search result
    def getOutput(self):
        return self.result

    # output resource error criteria
    def getStatus(self):
        if self.error == 'failed':
            Status = False
        else:
            Status = True

        return Status

    #Get VPCs based on the provided criteria in configuratiion
    def getVPCs(self, config):
        # vpc list placeholder
        vpcs = []
        # build up boto3 client for EC2
        ec2 = boto3.resource('ec2', region_name=self.region)
        # Loop through the vps within the account
        for vpc in ec2.vpcs.all():
            # I found a vpc, let's inspect the tags,
            if vpc.tags and self.searchObject(vpc.tags, config):
                # I found the name tag, let's check if the sdlcEnv is found within the value
                logger.info (f'Found a vpc: {vpc.id}')
                # We found the correct VPC matching criteria
                vpcs.append(vpc.id)
            #if no tag specified in configuration, return all vpcs
            elif not 'Tags' in config:
                vpcs.append(vpc.id)
        # turn list into a comma separated string and place it in our response
        self.setOutput(vpcs)

    #Get Subnets based on the provided criteria in configuratiion
    def getSubnets(self, config, vpclist):
        # subnets list placeholder
        subnetdict = {}
        # build up boto3 client for EC2
        ec2 = boto3.resource('ec2', region_name=self.region)

        # Loop through VPC(s)
        for vpcid in vpclist:
            # Use the vpcid parameter to create a vpc object
            logger.info(f'VPC id = {vpcid}')
            vpc = ec2.Vpc(vpcid)
            logger.info('f VPC object: {vpc}')
            # Loop through subnets
            for subnet in vpc.subnets.all():
                logger.info(f'subnet: {subnet.id}')
                # I found a subnet, ;let's inspect the tags
                if subnet.tags and self.searchObject(subnet.tags, config):
                    # subnet macth criteria; let's verify available IP
                    # we want to return only subnets with number of availablle IP
                    # specified in configuration
                    if subnet.available_ip_address_count > self.availableIp:
                        subnetdict[subnet.id] = subnet.available_ip_address_count
                        logger.info (f'free ips: {subnet.available_ip_address_count}')
                # if not tags criteria specified in configuration, return all subnets
                elif not subnet.tags and not 'Tags' in config:
                    # Verify available IP
                    if subnet.available_ip_address_count > self.availableIp:
                        subnetdict[subnet.id] = subnet.available_ip_address_count
                        logger.info (f'free ips: {subnet.available_ip_address_count}')

        # look at our dict, should contain subnets with free ips
        logger.info(f'Subnet list = {subnetdict}')
        # turn dict into a string to allow the shuffling.
        subnetlist = list(subnetdict.keys())
        # randomize the list to prevent constant selection of a subnet by position.
        random.shuffle(subnetlist)
        # turn list into a comma separated string and place it in our response
        self.setOutput(subnetlist)

    # Get Security Group based on the provided criteria in configuratiion
    def getSecurityGroup(self, config, vpclist):
        # Security Group placeholder
        securityGroups = []
        # Filter the security groups by the correct VPC
        sgfilter = [{'Name': 'vpc-id', 'Values': vpclist}]
        logger.info(f' my filter is {sgfilter}')
        # build up boto3 client for ec2 and get the list of security groups
        ec2 = boto3.client('ec2', region_name=self.region)
        paginator = ec2.get_paginator('describe_security_groups')
        page_iterator = paginator.paginate(Filters=sgfilter)

        for page in page_iterator:
            # Iterate through all security group
            for sg in page['SecurityGroups']:
                # if security group name provided
                if self.groupName:
                    # check if match
                    if self.groupName in sg['GroupName']:
                        # if sg has assign tags check tags criteria
                        if 'Tags' in sg:
                            if self.searchObject(sg['Tags'], config):
                                logger.info(f'found our security group {sg["GroupId"]} ')
                                securityGroups.append(sg['GroupId'])
                        # if not tags criteria specified in configuration, return sg
                        elif not 'Tags' in config:
                            logger.info(f'found our security group {sg["GroupId"]} ')
                            securityGroups.append(sg['GroupId'])
                # if sg has assign tags check tags criteria
                elif 'Tags' in sg and self.searchObject(sg['Tags'], config):
                    logger.info(f'found our security group {sg["GroupId"]} ')
                    securityGroups.append(sg['GroupId'])
                # if sg doens't have tags and no tags criteria specified in configuration, return all sg
                elif not 'Tags' in sg and not 'Tags' in config:
                    logger.info(f'found our security group {sg["GroupId"]} ')
                    securityGroups.append(sg['GroupId'])
        # turn list into a comma separated string and place it in our response
        self.setOutput(securityGroups)

    # Get ACM Certificates based on the provided criteria in configuratiion
    def getACM(self, config):
        cert_arn = []
        acm = boto3.client('acm', region_name=self.region)
        paginator = acm.get_paginator('list_certificates')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            # Iterate through certificates
            for cert in page['CertificateSummaryList']:
                # Get certificate tags
                acmTags = acm.list_tags_for_certificate(
                    CertificateArn=cert['CertificateArn']
                )
                # If cert domain provided
                if self.domain:
                    # check if the value match domain name
                    if self.domain in cert['DomainName']:
                        # if acm has tags, check tags criteria
                        if 'Tags' in acmTags:
                            if self.searchObject(acmTags['Tags'], config):
                                cert_arn.append(cert['CertificateArn'])
                        # if not tags criteria specified in configuration, return acm
                        elif not 'Tags' in config:
                            cert_arn.append(cert['CertificateArn'])
                # if no domain name provided but tag present, check tag criteria
                elif 'Tags' in acmTags and self.searchObject(acmTags['Tags'], config):
                    cert_arn.append(cert['CertificateArn'])
        # turn list into a comma separated string and place it in our response
        self.setOutput(cert_arn)

    # Get KMS Keys based on the provided criteria in configuratiion
    def getKMS(self):
        # build up boto3 client for KMS
        kmsKeys = []
        kms = boto3.client('kms', region_name=self.region)
        paginator = kms.get_paginator('list_aliases')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            # Iterate through keys
            for key in page['Aliases']:
                # depend on configuration return either key alias or id
                k = (key['AliasName'] if self.kmsOutput == 'alias' and 'TargetKeyId' in key else
                        (key['TargetKeyId'] if self.kmsOutput == 'id' and 'TargetKeyId' in key
                            else None))
                # if alias has associate key
                if k:
                    #check if alias criteria provided in configuration and match with curent alias
                    if self.kmsAlias and self.kmsAlias in key['AliasName']:
                        kmsKeys.append(k)
                    # if alias criteria not provided return all keys
                    elif not self.kmsAlias:
                        kmsKeys.append(k)
        # turn list into a comma separated string and place it in our response
        self.setOutput(kmsKeys)

    # Get IAM Policy based on the provided criteria in configuratiion
    def getPolicy(self):
        # build up boto3 client for iam
        policyArn=[]
        iam = boto3.client('iam', region_name=self.region)
        paginator = iam.get_paginator('list_policies')
        page_iterator = paginator.paginate(Scope='Local')

        for page in page_iterator:
            # Iterate through policies
            for policy in page['Policies']:
                # if policy name provided in configuration check if match with current policy
                if self.policyName and policy['PolicyName'].__contains__(self.policyName):
                    policyArn.append(policy['Arn'])
                # if no policy name provided return all policies
                elif not self.policyName:
                    policyArn.append(policy['Arn'])
        # turn list into a comma separated string and place it in our response
        self.setOutput(policyArn)

    # Get IAM Roles based on the provided criteria in configuratiion
    def getRoles(self, config):
        # build up boto3 client for iam
        rolesArn=[]
        iam = boto3.client('iam')
        paginator = iam.get_paginator('list_roles')
        page_iterator = paginator.paginate(PathPrefix=self.rolePath)

        for page in page_iterator:
            # Iterate through roles
            for role in page['Roles']:
                # get role tags
                roleTags = iam.list_role_tags(RoleName=role['RoleName'])
                # if role name criteria provided
                if self.roleName:
                    # check if it match with current role
                    if self.roleName in role['RoleName']:
                        # if role has tags, check if it macth with tag criteria
                        if 'Tags' in roleTags:
                            if self.searchObject(roleTags['Tags'], config):
                                rolesArn.append(role['Arn'])
                        # if mo tag criteria provided, retur nrole
                        elif not 'Tags' in config:
                            rolesArn.append(role['Arn'])
                # if no role name criteria provided in configuration, check tag criteria only
                elif 'Tags' in roleTags and self.searchObject(roleTags['Tags'], config):
                    rolesArn.append(role['Arn'])
                # if role doens't have tags and no tags criteria specified in configuration, return all roles
                elif not 'Tags' in roleTags and not 'Tags' in config:
                    rolesArn.append(role['Arn'])
        # turn list into a comma separated string and place it in our response
        self.setOutput(rolesArn)

    # depend on configuration either return first item from list
    # or all items converted to comma separated string
    def setOutput(self, resultList):
        if not resultList:
            self.result = ''
        elif self.output == 'single':
            self.result = resultList[0]
        else:
            self.result = ','.join(resultList)

    # Check if tags criteria provided
    # if so check if tags on resource match tag criteria
    def searchObject(self, tags, cfg):
        findObj = False
        if 'Tags' in cfg:
            findTag = []
            for t in cfg['Tags']:
                if self.searchTag(tags, t['Key'], t['Value']):
                    findTag.append('y')
            # depend on configuration check if either any tag or all tags matching provided criteria
            findObj = (True if (self.match == 'any' and len(findTag) > 0) or (len(findTag) == len(cfg['Tags'])) else False)
        else:
            findObj = True

        return findObj

    # check if any tag match criteria
    def searchTag(self, tags, kay, patern):
        findName = False
        for t in tags:
            # make key name not case sesitive
            # check if key match
            if t['Key'].lower() == kay.lower():
                # check if value match using regulare expression
                if re.search(patern, t['Value']):
                    findName = True
                    break
        return findName

    # convert comma delimiter lis tof VPCs to list
    # if vpc string is empty, add all available vpcs to list
    def convert_vps_to_list(self, vpc):
        vpclist = []
        if vpc:
            vpclist = vpc.split(',')
        else:
            # get all vpcs if vpc parameter empty
            ec2 = boto3.resource('ec2', region_name=self.region)
            for vpc in ec2.vpcs.all():
                vpclist.append(vpc.id)

        return vpclist

def lambda_handler(event, context):
    # We will store our result here
    responsedata = {}
    failed_on_error = True

    # check configuration if failed CFN satck if resource not found
    def checkStatus(resource, rs):
        if failed_on_error or not rs.getStatus():
            responsedata[resource] = 'Error: Resource {} not found'.format(resource)
            logger.info(f'Response data: + {responsedata}')
            # send failed status back to CFN
            cfnsend(event, context, 'FAILED', responsedata)
            return False
        else:
            return True


    # Need to make sure we don't waste time if the request type is
    # update or delete.  Exit gracefully
    if event['RequestType'] == "Delete":
        logger.info(f'Request Type is Delete; unsupported')
        cfnsend(event, context, 'SUCCESS', responsedata)
        return event
    if event['RequestType'] == "Update":
        logger.info(f'Request Type is Update; unsupported')
        cfnsend(event, context, 'SUCCESS', responsedata)
        return event

    # iterate through resources
    if 'Resources' in event['ResourceProperties']:
        # get name of resources
        res_list = (event['ResourceProperties']['Resources']).keys()

        # check global congfig how to handle not found resource
        # if Options -> Error = failed - failed CFN stack if any resource not found
        # otherwise check Error configuration for each idividual resource
        if 'Options' in res_list and 'Error' in event['ResourceProperties']['Resources']['Options']:
            if event['ResourceProperties']['Resources']['Options']['Error'] != 'failed':
                failed_on_error = False

        vpc=None
        # search for VPC(s)
        if 'vpc' in res_list:
            # call resource selector class to search for VPC based on the specify criteria
            rs = ResourceSelector(region=region, resource='vpc',cfg=event['ResourceProperties']['Resources']['vpc'])
            # get search result to local variable
            # that can be reuse with subnets and/or security group resources
            vpc = rs.getOutput()
            # output search result
            responsedata['vpc'] = vpc
            # if VPC not found, check if failed CFN
            if not responsedata['vpc'] and not checkStatus('vpc', rs):
                return responsedata
            # destroy class
            del rs

        # search for Subnet(s)
        if 'subnet' in res_list:
            # call resource selector class to search for subnet based on the specify criteria
            rs = ResourceSelector(region=region, resource='subnet',cfg=event['ResourceProperties']['Resources']['subnet'],vpc=vpc)
            # output search result
            responsedata['subnet'] = rs.getOutput()
            # if Subnet not found, check if failed CFN
            if not responsedata['subnet'] and not checkStatus('subnet', rs):
                return responsedata
            # destroy class
            del rs

        # search for security group(s)
        if 'sg' in res_list:
            # call resource selector class to search for security group based on the specify criteria
            rs = ResourceSelector(region=region, resource='sg',cfg=event['ResourceProperties']['Resources']['sg'],vpc=vpc)
            # output search result
            responsedata['sg'] = rs.getOutput()
            # if security group not found, check if failed CFN
            if not responsedata['sg'] and not checkStatus('sg', rs):
                return responsedata
            # destroy class
            del rs

        # search for ACM certificate(s)
        if 'acm' in res_list:
            # call resource selector class to search for acm certificate based on the specify criteria
            rs = ResourceSelector(region=region, resource='acm',cfg=event['ResourceProperties']['Resources']['acm'])
            # output search result
            responsedata['acm'] = rs.getOutput()
            # if acm certificate not found, check if failed CFN
            if not responsedata['acm'] and not checkStatus('acm', rs):
                return responsedata
            # destroy class
            del rs

        # search for KMS key(s)
        if 'kms' in res_list:
            # call resource selector class to search for kms key based on the specify criteria
            rs = ResourceSelector(region=region, resource='kms',cfg=event['ResourceProperties']['Resources']['kms'])
            # output search result
            responsedata['kms'] = rs.getOutput()
            # if kms key not found, check if failed CFN
            if not responsedata['kms'] and not checkStatus('kms', rs):
                return responsedata
            # destroy class
            del rs

        # search for IAM policy(s)
        if 'policy' in res_list:
            # call resource selector class to search for IAM policy based on the specify criteria
            rs = ResourceSelector(region=region, resource='policy',cfg=event['ResourceProperties']['Resources']['policy'])
            # output search result
            responsedata['policy'] = rs.getOutput()
            # if IAM policy not found, check if failed CFN
            if not responsedata['policy'] and not checkStatus('policy', rs):
                return responsedata
            # destroy class
            del rs

        # search for IAM role(s)
        if 'role' in res_list:
            # call resource selector class to search for IAM role based on the specify criteria
            rs = ResourceSelector(region=region, resource='role',cfg=event['ResourceProperties']['Resources']['role'])
            # output search result
            responsedata['role'] = rs.getOutput()
            # if IAM role not found, check if failed CFN
            if not responsedata['role'] and not checkStatus('role', rs):
                return responsedata
            # destroy class
            del rs

    # Log response data
    logger.info(f'Response data: + {responsedata}')

    # Using the cfnsend function to format our response to Cloudforamtion and send it
    cfnsend(event, context, 'SUCCESS', responsedata)
    return responsedata

def cfnsend(event, context, responseStatus, responseData, phyResId=None):
    responseUrl = event['ResponseURL']
    # Build out the response json
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'CWL Log Stream =' + context.log_stream_name
    responseBody['PhysicalResourceId'] = phyResId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['Data'] = responseData
    json_responseBody = json.dumps(responseBody)

    logger.info(f'Response body: + {json_responseBody}')

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }
    #Send response back to CFN
    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        logger.info(f'Status code: {response.reason}')
    except Exception as e:
        logger.info(f'send(..) failed executing requests.put(..):  + {str(e)}')
