# Product Selector Lambda

__`Product Selector`__ is an AWS Lambda function that was designed to be called from within an AWS CloudFormation as a [custom resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html). 


## AWS Service Catalog Product Identification

Return resource ids of product and artifact (version) required to launch an AWS Service Catalog product from AWS CloudFormation.  
This improves the end user experience because they do not need to remember specific resource identifiers.

__Example Syntax from with CloudFormation:__
```yaml
ProductSelector:
  Type: "Custom::ProductSelector"
  Version: "1.0"
  Properties:
    ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:sc-product-selector'
    ProductName: <product name e.g. sqs>
    Version: <version of product to return id>
```

__Note__: Version parameter is optional. If not provided, latest version will be return.

__Example Syntax of obtaining the Returned Values:__

Product Id: `!GetAtt ProductSelector.ProductId`

Provisioning Artifact Id: `!GetAtt ProductSelector.ArtifactId`


__Example of Usage:__

Please refer to the AWS CloudFormation product provision templates in the `templates\examples` folder.
