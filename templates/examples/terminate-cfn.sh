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

resource_stack_name="sc-test-resources-cfn"

aws cloudformation delete-stack --stack-name sc-dms-endpoint-cfn
aws cloudformation delete-stack --stack-name sc-dms-instance-cf
aws cloudformation delete-stack --stack-name sc-dynamodb-cfn
aws cloudformation delete-stack --stack-name sc-ebs-cfn
aws cloudformation delete-stack --stack-name sc-efs-cfn
aws cloudformation delete-stack --stack-name sc-elasticache-cfn
aws cloudformation delete-stack --stack-name sc-elasticsearch-cfn
aws cloudformation delete-stack --stack-name sc-fsx-cfn
aws cloudformation delete-stack --stack-name sc-kinesis-cfn
aws cloudformation delete-stack --stack-name sc-sagemaker-cfn
aws cloudformation delete-stack --stack-name sc-sns-cfn
aws cloudformation delete-stack --stack-name sc-sqs-cfn

# Wait 5 minutes for ElasticSearch and ELastiCache termination
sleep 300
aws cloudformation delete-stack --stack-name $resource_stack_name
