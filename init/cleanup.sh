#!/bin/bash

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

resources_cfn_stack_name="sc-product-resources"
lambda_functions_cfn_stack_name="sc-lambda-functions"
deployment_lambda_function_name="sc-product-deployment"
deployment_s3_bucket_name="<enter the name of Amazon S3 bucket that will be use to deploy solution>"
aws_cli_profile="default"

products_to_deploy=(sqs kinesis sns elasticsearch elasticache ebs efs dmsinstance dmsendpoint autoscaling alb albtarget alblistener fsx dynamodb sagemaker s3 kms mq governance-lambdas governance-lambda-roles vpc subnet firehose)
delete_products="yes"

# check if the name of deployment S3 bucket provided in script argument
if [[ $1 != '' ]]
then
  deployment_s3_bucket_name=$1
fi

if [[ $deployment_s3_bucket_name = '' ]]
then
  echo "Usage: cleanup.sh <S3 Deployment Bucket Name> <optional: aws cli profile name>"
  exit 1
fi

if [[ $2 != '' ]]
then
  aws_cli_profile=$2
fi

printf "\nCleanup using CLI profile: $aws_cli_profile\n\n"

if [ $delete_products == "yes" ]
then
  for i in ${products_to_deploy[*]}
  do
    printf "Deleting Product: $i\n"
    aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name "sc-$i-product-cfn" --profile $aws_cli_profile
    aws cloudformation delete-stack --stack-name "sc-$i-product-cfn" --profile $aws_cli_profile
  done

  sleep 20
fi

if [[ -z $1 ]]
then
  s3_bucket_arn=$(aws cloudformation describe-stacks --query 'Stacks[?Tags[?Key==`SC:Automation` && Value==`sc-deployment-bucket`][]].Outputs[0].OutputValue' --profile $aws_cli_profile --output text)
  deployment_s3_bucket_name=${s3_bucket_arn/arn:aws:s3:::/}
fi

printf "Deleting Lambda Functions\n"
aws cloudformation delete-stack --stack-name $lambda_functions_cfn_stack_name --profile $aws_cli_profile

printf "Cleaning S3 Bucket: $deployment_s3_bucket_name\n"
echo '#!/bin/bash' > deleteBucketScript.sh && aws --output text s3api list-object-versions --bucket $deployment_s3_bucket_name --profile $aws_cli_profile | grep -E "^VERSIONS" | awk '{print "aws s3api delete-object --profile $aws_cli_profile --bucket $deployment_s3_bucket_name --key "$4" --version-id "$8";"}' >> deleteBucketScript.sh && . deleteBucketScript.sh; rm -f deleteBucketScript.sh; echo '#!/bin/bash' > deleteBucketScript.sh && aws --output text s3api list-object-versions --bucket $deployment_s3_bucket_name --profile $aws_cli_profile | grep -E "^DELETEMARKERS" | grep -v "null" | awk '{print "aws s3api delete-object --bucket $deployment_s3_bucket_name --profile $aws_cli_profile --key "$3" --version-id "$5";"}' >> deleteBucketScript.sh && . deleteBucketScript.sh; rm -f deleteBucketScript.sh;

printf "Deleting S3 Bucket: $deployment_s3_bucket_name\n"
aws s3 rb s3://$deployment_s3_bucket_name --force --profile $aws_cli_profile

printf "Deleting CFN Resource\n"
aws cloudformation delete-stack --stack-name $resources_cfn_stack_name-s3-bucket --profile $aws_cli_profile
aws cloudformation delete-stack --stack-name $resources_cfn_stack_name --profile $aws_cli_profile

printf "Cleanup Conpleted\n"
