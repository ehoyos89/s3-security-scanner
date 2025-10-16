#!/bin/bash
# deploy.sh

# Variables
AWS_REGION="us-east-1"
AWS_ACCOUNT_ID="766557581633"
ECR_REPO_NAME="s3-security-scanner"
LAMBDA_FUNCTION_NAME="s3-security-scanner"
IMAGE_TAG="latest"

# Construir imagen
docker build -t ${ECR_REPO_NAME}:${IMAGE_TAG} .

# Login a ECR
aws ecr get-login-password --region ${AWS_REGION} |
  docker login --username AWS --password-stdin \
    ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Tag de la imagen
docker tag ${ECR_REPO_NAME}:${IMAGE_TAG} \
  ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}

# Push a ECR
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}

# Actualizar Lambda
aws lambda update-function-code \
  --function-name ${LAMBDA_FUNCTION_NAME} \
  --image-uri ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}
