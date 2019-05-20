# Product Deployment Lambda

__`sc-product-deployment-lambda`__ is the AWS Lambda function responsible for adding new products to AWS Service Catalog as well as creating the product’s IAM Service Catalog role. 

To add a new product to AWS Service Catalog, you will need to upload a product configuration file to the Amazon S3 deployment bucket. 
The configuration file has to have the extension specified in the solution deployment script. 
The default extension is `.deployer`.  

## Configuration File Format
The configuration file’s content has to be in JSON readable format.  Most editors have a json editing tool that can be used to validate json syntax.   Below is an example of the configuration file.  
```json
{
  "Parameters": {
    "PorfolioStack": "<name of the CloudFormation stack used to create Service Catalog portfolio>",
    "ProductName": "<product name>",
    "ProductDescription": "<product description>",
    "ProductVersion": "<product initial version e.g. 1.0>",
    "ProductVersionDescription": "<product version description>",
    "ProductTemplateUrl": "<path to product CloudFormation template, including S3 bucket name>",
    "ProductRoleName": "<name of the Service Catalog product IAM role>",
    "ProductPolicyName": "<name of the product IAM policy",
    "ProductRoleTemplateUrl": "<path to product IAM role Cloudformation template, including S3 bucket name>",
    "TemplateRuleConstraint": "< (optional), Service Catalog template rule constraint>",
    "DeploymentBucket": "<deployment bucket>",
    "DeployUpdatePipeline": "< true/false>",
    "UpdateConfigFileName": "<name of the file to trigger update pipeline without extension>"
  }
}
```

The values for the parameters: `PorfolioStack`, `ProductPolicyName` and `DeploymentBucket` should be the same values provided in the solution deployment script.

Copies of the configuration files can be found in products-config folder after running the solution deployment script. 
This can be used to validate your current configuration.  For example, the value of `TemplateRuleConstraint` can be found in the `products-config\sc-product-elasticsearch.deployer` file. 

## Deployment

We are organizing all of the product assets within the same S3 prefix.  As an example, `<s3-deployment-bucket>/products/`.  
Each product will have its own prefix as well.  For instance, `< s3-deployment-bucket>/products/sqs`.  
To deploy a new product, follow these steps:

* Upload the IAM Role and product CFN templates to the Amazon S3 bucket (<s3-deployment-bucket>) using the S3 prefix <products/productname>.  
* Create a configuration file pointing to the location where templates where uploaded
* Upload the configuration file to <s3-deployment-bucket>/deployment-cfg folder

The upload to S3 will trigger the sc-product-deployment-lambda function.  
This function will launch the product deployment CloudFormation template located at `<s3-deployment-bucket>/deployment-cfn/sc-product-deployment.yml`. 

AWS CloudFormation parameters value will be read from the configuration file. 
