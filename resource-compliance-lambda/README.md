# Resource Compliance Lambda 

AWS CloudFormation custom resources provide the ability to run custom logic during a CFN template’s execution.  
This feature can allow us to perform additional compliances checks or configuration steps on resources we are creating.  
The Resource Compliance Lambda is an example of this and provides the following capabilities:

## Bring You Own Key (BYOK)

This capability validates if the provided KMS key has external key material using the KMS Import Key feature. 

__Syntax:__

```yaml
ProductSelector:
  Type: "Custom:: ResourceCompliance"
  Version: "1.0"
  Properties:
    ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function: sc-resource-compliance’
    Action:
        Name: byok
        Parameters:
          	Key: <KMS Key Id to validate>
```

__Return:__

If provided KMS Key doesn’t have EXTERNAL origin, this indicated it is not an imported key.  
The function will return a FAILURE status back to AWS CloudFormation.  This will cause the stack to fail.  

## JSON

This capability convert provided string to JSON object. The input string has following format:

`“Key1=Value1,Key2=Value2,…”`

__Example:__

`“Name=My Cluster,Environment=Dev”`

The input string can be convert to four different output formats which are:
 
### Tags:

Tags type convert input string to following format:

	`[{“Key”:Key1, “Value”: Valu1},{“Key”:Key2, “Value”,Value2},…]`
  
__Example:__

`[{“Key”:”Name”, “Value”: “My Cluster”},{“Key”:”Environment”, “Value”,”Dev”}]`

Converted string is return as JSON object back to CFN templates where can be use as value for any resource Tags parameter.
For usage example see CFN templates in `templates/examples/` location

### DynamoDBSchema:

This type convert input string to Amazon DynamoDB Attribute Definition format:

`[{“AttributeName”:Key1,“AttributeType”:Valu1},{“AttributeName”:Key2, “AttributeType”,Value2},….]`

__Example:__

`[{“AttributeName”:”Name”, “AttributeType”: “S”},{“ AttributeName”:”Id”, “AttributeType”,”S”}]`

Converted string is return as JSON object back to CFN where can be apply to Amazon DynamoDB product. 
For usage example see CFN template in `templates/examples/sc-provision-dynamodb-cft.yml`

For supported AttributeType value visit: [https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_AttributeDefinition.html](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_AttributeDefinition.html)

### DynamoDBKey

This type convert input string to Amazon DynamoDB Key Schema format:

`[{“AttributeName”:Key1, “KeyType”: Valu1},{“ AttributeName”:Key2, “KeyType”,Value2},…]`

__Example:__

`[{“AttributeName”:”Name”, “KeyType”: “HASH”},{“ AttributeName”:”Id”, “KeyType”,”RANGE”}]`

Converted string is return as JSON object back to CFN where can be apply to Amazon DynamoDB product. 
For usage example see CFN template in `templates/examples/sc-provision-dynamodb-cft.yml`

For supported “KeyType” value visit: [https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_KeySchemaElement.html](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_KeySchemaElement.html)

### SQS

This type convert input string to tags and apply them to Amazon SQS, as currently AWS CloudFormation does not support Amazon SQS tagging.

`{“Key”:Key1, “Value”: Valu1},{“Key”:Key2, “Value”,Value2},…`

__No JSON return__

__Note__: the SQS queue URL must be provided under SQS parameter
For usage example see AWS Service Catalog SQS product template: 
`s3-upload-files/products/sqs/sc-sqs.yml`


__Syntax:__

```yaml
ResourceCompliance:
  Type: "Custom:: ResourceCompliance"
  Version: "1.0"
  Properties:
    ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function: sc-resource-compliance’
    Action:
        Name: json
        Parameters:
          JSON: ‘<comma delimiter key=value string>’
          Type: <Convert type: tags, sqs, dynamodbschema, dynamodbkey>
          SQS: <SQS Queue URL. Require when Type is sqs>
```

__Return:__

This capability return JSON object, except when type is ‘sqs’.

__Example of Usage__

See links under each convert type

## Principal

This capability ensures that the provided principal for the access policy is not a wildcard (*). 
If a wildcard value is passed, the wildcard will be replaced with AWS account Id of the account.

__Syntax:__

```yaml
ProductSelector:
  Type: "Custom:: ResourceCompliance"
  Version: "1.0"
  Properties:
    ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function: sc-resource-compliance’
    Action:
        Name: principal
        Parameters:
          Account: <AWS Account Id>
          Principal: <List of principals>
```

__Return:__

This capability does not return any values.

__Example of Usage__

See sc-elasticsearch.yml cfn template in `s3-upload-files\products\elasticsearch location`
