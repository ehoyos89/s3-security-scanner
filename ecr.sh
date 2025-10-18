#!/bin/bash
# deploy.sh

# Variables
AWS_REGION=""
AWS_ACCOUNT_ID=""
ECR_REPO_NAME=""
LAMBDA_FUNCTION_NAME=""
IMAGE_TAG=""

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
