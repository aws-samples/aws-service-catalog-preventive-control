#!/bin/bash

# /*
# * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# Domain Name of SSL Cert import to ACM
domain_name="www.example.com"

# optional AWS CLI profile. If not provided default profile will be used.
aws_cli_profile="default"

if [[ $1 != '' ]]
then
  aws_cli_profile=$1
fi

printf "Deploying under AWS CLI Profile: $aws_cli_profile\n"

printf "Creating Service Linked Role"
aws iam create-service-linked-role --aws-service-name autoscaling.amazonaws.com --profile $aws_cli_profile
aws iam create-service-linked-role --aws-service-name elasticloadbalancing.amazonaws.com --profile $aws_cli_profile

printf "Generate and Import Self-Sign SSL Certificate to ACM\n"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certificate.key -out certificate.crt -subj "/C=US/ST=MA/L=Boston/O=Company/OU=IT/CN=$domain_name"
certArn=$(aws acm import-certificate --certificate file://./certificate.crt --private-key file://./certificate.key --query 'CertificateArn' --region us-east-1 --profile $aws_cli_profile --output text)
aws acm add-tags-to-certificate --certificate-arn $certArn --tags Key=Name,Value=sc-demo --region us-east-1 --profile $aws_cli_profile

printf "\Certificate Imported to ACM\n"
