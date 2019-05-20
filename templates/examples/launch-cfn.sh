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

# Name of the CF Resource stack
resource_stack_name="sc-test-resources-cfn"

# In order to deploy and test FSx template you need AWS Directory Service
# Fill information below to launch FSx
# Change to true if you want to test FSx
deployFSx=false
# id of AWS Directory Service
directory_service_id=""
# subnet in which AWS DS was launch
directory_subnet=""
# SG for AWS DS - has to be in the same VPC as DS
directory_security_group=""

printf "Launching CF Resource Stack\n"
stackId=$(aws cloudformation create-stack --stack-name $resource_stack_name --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --template-body file://sc-test-resources-cfn.yml --query 'StackId' --output text)
if [ -z $stackId ]
then
  printf "Stack failed to launch\n"
  exit 1
fi

cfStat=$(aws cloudformation describe-stacks --stack-name $resource_stack_name --query 'Stacks[0].[StackStatus]' --output text)
printf "Waiting for CF Resource Stack to Finish ..."
while [[ $cfStat != "CREATE_COMPLETE" ]]
do
  sleep 5
  printf "."
  cfStat=$(aws cloudformation describe-stacks --stack-name $resource_stack_name --query 'Stacks[0].[StackStatus]' --output text)
  if [[ $cfStat = "CREATE_FAILED" ]]
  then
    printf "\nCFN Stack Failed to Create\n"
    exit 1
  fi
done
printf "\nCF Resource Stack Launched\n"
cfOutput=$(aws cloudformation describe-stacks --stack-name $resource_stack_name --query 'Stacks[0].[Outputs][]' --output json)

# Get output values from CF Resource stack
subA=$(echo $cfOutput | jq --raw-output '.[] | select(.OutputKey == "SubnetA").OutputValue')
subB=$(echo $cfOutput | jq --raw-output '.[] | select(.OutputKey == "SubnetB").OutputValue')
kms=$(echo $cfOutput | jq --raw-output '.[] | select(.OutputKey == "TestKMS").OutputValue')
sg=$(echo $cfOutput | jq --raw-output '.[] | select(.OutputKey == "TestSG").OutputValue')
dmssub=$(echo $cfOutput | jq --raw-output '.[] | select(.OutputKey == "DMSGroup").OutputValue')
ecsub=$(echo $cfOutput | jq --raw-output '.[] | select(.OutputKey == "ECSubnet").OutputValue')
ecsg=$(echo $cfOutput | jq --raw-output '.[] | select(.OutputKey == "ECSG").OutputValue')
smrole=$(echo $cfOutput | jq --raw-output '.[] | select(.OutputKey == "SMRole").OutputValue')

printf "Copy Configuration Files\n"
# Create parameter folder and copy configuration files
mkdir -p parameters
cp -f configs/* parameters/

#Get OS Name
getOS=$(uname -s)
printf "Updating Configuration Files\n"
for filename in parameters/*.json
do
  echo "Updating: "$filename
  if [ $getOS = "Darwin" ]
  then
    sed -i '' 's/var.kms/'$kms'/g' $filename
    sed -i '' 's/var.dmssubnet/'$dmssub'/g' $filename
    sed -i '' 's/var.sg/'$sg'/g' $filename
    sed -i '' 's/var.cachesubnet/'$ecsub'/g' $filename
    sed -i '' 's/var.subnet/'$subA'/g' $filename
    sed -i '' 's/var.smrole/'$smrole'/g' $filename

    if [ $deployFSx = true ] && [ $filename = "parameters/fsx.json" ]
    then
      sed -i '' 's/"var.kms/'$kms'/g' $filename
      sed -i '' 's/var.adsubnet/'$directory_subnet'/g' $filename
      sed -i '' 's/var.adsg/'$directory_security_group'/g' $filename
      sed -i '' 's/var.ad/'$directory_service_id'/g' $filename
    fi
  else
    sed -i 's/var.kms/'$kms'/g' $filename
    sed -i 's/var.dmssubnet/'$dmssub'/g' $filename
    sed -i 's/var.sg/'$sg'/g' $filename
    sed -i 's/var.cachesubnet/'$ecsub'/g' $filename
    sed -i 's/var.subnet/'$subA'/g' $filename
    sed -i 's/var.smrole/'$smrole'/g' $filename

    if [ $deployFSx = true ] && [ $filename = "parameters/fsx.json" ]
    then
      sed -i 's/"var.kms/'$kms'/g' $filename
      sed -i 's/var.adsubnet/'$directory_subnet'/g' $filename
      sed -i 's/var.adsg/'$directory_security_group'/g' $filename
      sed -i 's/var.ad/'$directory_service_id'/g' $filename
    fi
  fi
done

printf "Creating Service Catalog Products:\n"
printf "DMS Enpoint\n"
aws cloudformation create-stack --stack-name sc-dms-endpoint-cfn --template-body file://sc-provision-dms-endpoint-cft.yml --parameters file://parameters/dms-endpoint.json
printf "DMS Replication Instance\n"
aws cloudformation create-stack --stack-name sc-dms-instance-cf  --template-body file://sc-provision-dms-replication-instance-cft.yml --parameters file://parameters/dms-replication.json
printf "DynamoDB\n"
aws cloudformation create-stack --stack-name sc-dynamodb-cfn --template-body file://sc-provision-dynamodb-cft.yml --parameters file://parameters/dynamodb.json
printf "EBS\n"
aws cloudformation create-stack --stack-name sc-ebs-cfn --template-body file://sc-provision-ebs-cft.yml --parameters file://parameters/ebs.json
printf "EFS\n"
aws cloudformation create-stack --stack-name sc-efs-cfn --template-body file://sc-provision-efs-cft.yml --parameters file://parameters/efs.json
printf "ElastiCache\n"
aws cloudformation create-stack --stack-name sc-elasticache-cfn --template-body file://sc-provision-elasticache-cft.yml --parameters file://parameters/elasticache.json
printf "ElasticSearch\n"
aws cloudformation create-stack --stack-name sc-elasticsearch-cfn --template-body file://sc-provision-elasticsearch-cft.yml --parameters file://parameters/elasticsearch.json
if [ $deployFSx = true ]
then
  printf "FSx\n"
  aws cloudformation create-stack --stack-name sc-fsx-cfn --template-body file://sc-provision-fsx-cft.yml --parameters file://parameters/fsx.json
fi
printf "Kinesis\n"
aws cloudformation create-stack --stack-name sc-kinesis-cfn --template-body file://sc-provision-kinesis-cft.yml --parameters file://parameters/kinesis.json
printf "Sagemaker\n"
aws cloudformation create-stack --stack-name sc-sagemaker-cfn --template-body file://sc-provision-sagemaker-cft.yml --parameters file://parameters/sagemaker.json
printf "SNS\n"
aws cloudformation create-stack --stack-name sc-sns-cfn --template-body file://sc-provision-sns-cft.yml --parameters file://parameters/sns.json
printf "SQS\n"
aws cloudformation create-stack --stack-name sc-sqs-cfn --template-body file://sc-provision-sqs-cft.yml --parameters file://parameters/sqs.json
printf "S3\n"
aws cloudformation create-stack --stack-name sc-s3-cfn --template-body file://sc-provision-s3-cft.yml --parameters file://parameters/s3.json
printf "Deployment Finish !!!\n"
