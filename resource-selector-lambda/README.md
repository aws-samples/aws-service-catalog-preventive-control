# Resource Selector Lambda

One of the considerations when building this solution was scale.  
How much work is required from the team that administers the AWS Service Catalog portfolio and the development teams that uses the AWS Service Catalog products?  
In order to truly make this solution self-service we needed to provide a method for development teams to easily obtain AWS account specific resource ids that are required by the AWS Service Catalog products.  
The Resource Selector Lambda provides this service.  The Resource Selector Lambda is called as a customer resource in your AWS CloudFormation template.  
The Lambda function will return the AWS account specific values that are dependent on the parameters you pass into the function from the custom resource definition.

Resource Selector AWS Lambda function supports returning the following resource ids:
*	VPC
*	Subnets
*	Security Groups
*	AWS Certificate Manager
*	KMS Keys
*	IAM Policy
*	IAM Roles
*	Spot Price
*	Image Id (AMI)

__Usage__

Below is an AWS CloudFormation snippet with demonstrates the syntax and options supported by each resource:

```yaml
  ResourceSelector:
    Type: "Custom::ResourceSelector"
    Version: "1.0"
    Properties:
      ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:sc-resource-selector'
      Options:
        OnError : [optional] (skip,failed => default failed)
      Resources:
        vpc:
          Tags:
            - Key: <key name>
              Value: <value>
          Options:
            Output: [optional](single, all => default: all)
            Match: [optional](all, any => default: any)
            OnError: [optiona] (skip,failed => default: failed)
        subnet:
          Tags:
            - Key: <key name>
              Value: <value>
          Options:
            Output: [optional](single, all => default: all)
            Match: [optional](all, any => default: any)
            OnError: [optiona] (skip,failed => default: failed)
            AvailableIP: [optional] (number => default: 5)
        sg:
          Tags:
            - Key: <key name>
              Value: <value>
          Options:
            Output: [optional](single, all => default: all)
            Match: [optional](all, any => default: any)
            OnError: [optiona] (skip,failed => default: failed)
            GroupName: [optional] <security group name>

        acm:
          Tags:
            - Key: <key name>
              Value: <value>
          Options:
            Output: [optional](single, all => default: all)
            Match: [optional](all, any => default: any)
            OnError: [optiona] (skip,failed => default: failed)
            Domain: [optional] <certificate domain name>
        kms:
          Options:
            Output: [optional](single, all => default: all)
            OnError: [optiona] (skip,failed => default: failed)
            KMSAlias: [optional] <kms key alias>
            KMSOutput: [optional] (id, alias => default: id)
        policy:
          Options:
            Output: [optional](single, all => default: all)
            OnError: [optiona] (skip,failed => default: failed)
            PolicyName: [optional] <iam policy name>
        role:
          Tags:
            - Key: <key name>
              Value: <value>
          Options:
            Output: [optional](single, all => default: all)
            Match: [optional](all, any => default: any)
            OnError: [optiona] (skip,failed => default: failed)
            RoleName: [optional] <iam role name>
            RolePath: [optional] <iam role path>
        spot:
          Options:
            InstanceType: [require] <EC2 Instance Type>
            InstanceOS: [require] (Linux, Windows, RHEL)
        ami:
          Tags:
            - Key: <key name>
              Value: <value>
          Options:
            ImageOwner: [require](self,<account id>, amazon, etc.)
            ImageName: [optiona] < AMI image name>
```

## Parameters

All parameters are optional. If a parameter is not passed into the function, all resources will be returned.

### Tags

Allow a developer to search for resources by tags. This is a list; so you can use a single or multiple tags in the search. 

* `Key` – is the name of tag key. This value must match tag name associate with resource (is not case sensitive)
* `Value` – is the value of tag key. It can be a whole name, partial name or regular expression (this is case sensitive)

__Note:__ KMS and IAM Policy do not support search by tags

### Output

Specify how many resources should be returned, if more than one resource id  matches the search criteria.

__Allowed values:__

* `single` –returns the first resource that matches your criteria
* `all` – returns all resources matching the criteria

If this value is not provided, all resources matching the criteria will be returned

### Match

If multiple tags are provided, indicate if resource need to match on all or any tags

Allow values: `all`, `any`

If this value is not provided, all resources that match at least one tag will be returned

### OnError

Define how the AWS CloudFormation stack will behave if no resources match our criteria.

__Allow values:__

* `skip` – CFN stack will ignore empty value and keep continue running. Be aware that this might cause the CFN stack to fail if template was not design to handle an empty value
* `failed` – CFN stack will fail if resources are not found

If this value is not provided, the default behavior is to cause the stack to fail.

This option can be described in two places.  If it is described as a property of the function definition, then this value is applied globally to all subsequent resources.  If it is described within a specific resource, this value only applies to that resource.

### AvailableIP

This parameter allows  a developer to specify how many IPs have to be available in the subnet for the function to return it. The default is 5 IPs.

### Domain

Name of domain on the ACM certificate. The search domain can be provided as the whole or partial name 

### KMSAlias

KMS alias to search. The search alias can be provided as a whole or partial name.

### KMSOutput

Define if the function should return the found key(s) as an alias or a KMS id. Allow values: id, alias. Default value is `alias`. 

### PolicyName

A full or partial name of IAM policy to search for. Keep in mind; IAM policy do not support Tags

### RoleName

The full or partial name of the IAM role to search

### RolePath

IAM role path

### InstanceType

Appling to Spot Pricing - EC2 Instance Type for which the spot price should be return. Example: `t2.micro`

### InstanceOS

Appling to Spot Pricing – EC2 Instance operation system for which the spot price should be return. Allow values: `Linux`, `Windows`, `RHEL`

### ImageOwner

Applying for AMI – the owner of image. Can be `self`, `<account id>`, `amazon`, `microsoft`, `aws-marketpalce`

### ImageName

Applying for AMI – full or partial name of AMI image

__Note__: To narrow search of subnets or security group to specific VPC, define criteria for vpc resource as well. 
If VPC is not found, all subnets/security group will be return. To avoid this, set OnError = failed option under vpc resource.
