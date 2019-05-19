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
from botocore.vendored import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sc = boto3.client('servicecatalog')

responsedata = {}

def lambda_handler(event, context):
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

    # Check if product provided
    if not 'ProductName' in event['ResourceProperties']:
        logger.info(f'Product Not Provided')
        responsedata['Id'] = 'Product not provided'
        cfnsend(event, context, 'FAILED', responsedata, 'Product name was not provided in lambda invocation')
        return event

    # get product name from CFN calling lambda
    productName = f'sc-{event["ResourceProperties"]["ProductName"]}-product'
    logger.info(f'Searching product: {productName}')
    # search product in AWS Service Catalog
    response = sc.search_products_as_admin(
        SortBy='Title',
        SortOrder='ASCENDING',
        ProductSource='ACCOUNT',
        Filters={
                'FullTextSearch': [
                    productName
                ]
            }
    )

    productList=[]
    #Iterate through all return products
    for p in response['ProductViewDetails']:
        # find the searching product
        if productName in p['ProductViewSummary']['Name']:
            productList.append({'ProductId' : p['ProductViewSummary']['ProductId'], 'CreatedTime' : p['CreatedTime'] })

    # if product found
    if productList:
        # if more the on product get the latest one based on the date/time
        last_product_Id = max(productList,key=lambda item:item['CreatedTime'])
        prodId = last_product_Id['ProductId']
        responsedata['ProductId'] = prodId

        # search artifacts (versions) of product
        prodArtif = sc.list_provisioning_artifacts(
            AcceptLanguage='en',
            ProductId=prodId
        )

        # if version provided in cfn
        if 'Version' in event['ResourceProperties']:
            logger.info(f'Searching version: {event["ResourceProperties"]["Version"]}')
            for a in prodArtif['ProvisioningArtifactDetails']:
                # find artifact that match provided version
                if a['Name'] == event['ResourceProperties']['Version']:
                    responsedata['ArtifactId'] = a['Id']

            if not 'ArtifactId' in responsedata:
                logger.info('Version not found')
                responsedata['ArtifactId'] = 'Version not found'
                cfnsend(event, context, 'FAILED', responsedata, 'Version not found in Service Catalog')
                return event
        # otherwise return last one based on the date/time
        else:
            last_artifact_Id = max(prodArtif['ProvisioningArtifactDetails'],key=lambda item:item['CreatedTime'])
            responsedata['ArtifactId'] = last_artifact_Id['Id']

        logger.info(f'Respond Product Id: {responsedata["ProductId"]}')
        logger.info(f'Respond Artifact Id: {responsedata["ArtifactId"]}')
        # Return product info back to CFN
        cfnsend(event, context, 'SUCCESS', responsedata)
    else:
        # if product not found failed CFN
        logger.info('Product Not Found')
        responsedata['Id']='Product not found'
        cfnsend(event, context, 'FAILED', responsedata, 'Product not found in Service Catalog')

    return event


def cfnsend(event, context, responseStatus, responseData, reason=None):
    if 'ResponseURL' in event:
        responseUrl = event['ResponseURL']
        # Build out the response json
        responseBody = {}
        responseBody['Status'] = responseStatus
        responseBody['Reason'] = reason or 'CWL Log Stream =' + context.log_stream_name
        responseBody['PhysicalResourceId'] = context.log_stream_name
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
        # Send response back to CFN
        try:
            response = requests.put(responseUrl,
                                    data=json_responseBody,
                                    headers=headers)
            logger.info(f'Status code: {response.reason}')
        except Exception as e:
            logger.info(f'send(..) failed executing requests.put(..):  {str(e)}')
