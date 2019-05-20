## AWS Service Catalog Preventive Control

Large enterprises try to find a balance between controlling risk and empowering their developers in alignment with DevOps practices.   Ideally developers are able to leverage AWS services and create optimized architectures for their applications. This solution addresses the risk and empowerment concerns by using AWS Service Catalog to exposed hardened AWS services to developers.  By leveraging AWS Service Catalog products for each AWS Service; developers can create their own architectures with a self-service experience.  This solution provides CloudFormation templates to make it easier for developers to automate the provisioning of the Service Catalog products.

## License Summary

This sample code is made available under the MIT-0 license. See the LICENSE file.

## Content

Below are the descriptions of the content in each solution folder:

__deployment-lambda__ – source code of the AWS Lambda Function that handles the initial deployment of a Service Catalog product. 

__docs__ – documentation for this solution.

__init__ – AWS CloudFormation templates to create the required foundational infrastructure for the solution such as; IAM policies and roles, the AWS Service Catalog portfolio and an Amazon S3 bucket.

*	deploy.sh – located in Init folder.  Initial deployment shell script.
*	cleanup.sh – located in Init folder.  This script deletes all resources created by the deployment script

__products-config__ – (empty) – placeholder for product configuration files. The deployment script will copy the deployment templates from the templates\deployment folder to this folder and update it based on the configuration set in the deployment script.

__product-selector-lambda__ – source code of the AWS Lambda Function to support provisioning products. 

__resource-compliance-lambda__ – source code of the AWS Lambda Function to validate parameters when provisioning products. 

__resource-selector-lambda__ – source code of the AWS Lambda Function to support deployment by easily finding AWS resource such as vpc, subnet, security group, and other using tags and filters. 

__s3-upload-files__ – contains the AWS CloudFormation products deployment template and the AWS CloudFormation products template. The entire content of this folder will be copied to the deployment Amazon S3 bucket during initial solution deployment.
templates – various configuration and AWS CloudFormation templates:

* Deployment – product deployment configuration templates. See products-config folder description above.
* Examples – example of the AWS CloudFormation templates to provision each product from AWS Service Catalog.
* Updates – product update configuration files. For more information about update go to Product Update CodePipeline.
* sc-(product)-update.json – product update configuration template.
* deny-policy.yml – the AWS CloudFormation template to create deny IAM policy. This policy can be attached to IAM users or roles to prevent users create AWS resources that are supported by AWS Service Catalog, from AWS Management Console, cli, api, etc.

