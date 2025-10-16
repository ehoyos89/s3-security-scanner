# Guía de Despliegue Manual - S3 Security Scanner

Esta guía te ayudará a desplegar el proyecto manualmente paso a paso, sin usar scripts automáticos o CloudFormation.

## 📋 Prerrequisitos

- AWS CLI configurado con las credenciales apropiadas
- Docker instalado
- Permisos IAM para crear recursos en AWS

## 🗂️ Paso 1: Configurar Parámetros en AWS Parameter Store

El proyecto ahora usa AWS Parameter Store en lugar de variables de entorno. Configura los siguientes parámetros:

### Crear los parámetros:

```bash
# 1. Configurar el bucket donde se guardarán los reportes
aws ssm put-parameter \
    --name "/s3-scanner/reports-bucket" \
    --value "mi-bucket-reportes-seguridad" \
    --type "String" \
    --description "Bucket S3 para almacenar reportes de seguridad"

# 2. Configurar el ARN del tópico SNS (se creará en el paso siguiente)
# NOTA: Ejecutar este comando después del Paso 2
aws ssm put-parameter \
    --name "/s3-scanner/sns-topic-arn" \
    --value "arn:aws:sns:REGION:ACCOUNT:s3-security-alerts" \
    --type "String" \
    --description "ARN del tópico SNS para alertas de seguridad"

# 3. Configurar la región de AWS
aws ssm put-parameter \
    --name "/s3-scanner/aws-region" \
    --value "us-east-1" \
    --type "String" \
    --description "Región de AWS para el proyecto"
```

### Verificar parámetros creados:

```bash
aws ssm get-parameters \
    --names "/s3-scanner/reports-bucket" "/s3-scanner/aws-region" \
    --query "Parameters[*].[Name,Value]" \
    --output table
```

## 📧 Paso 2: Crear Tópico SNS para Notificaciones

```bash
# Crear el tópico SNS
TOPIC_ARN=$(aws sns create-topic \
    --name "s3-security-alerts" \
    --query "TopicArn" \
    --output text)

echo "Tópico SNS creado: $TOPIC_ARN"

# Suscribir tu email al tópico
aws sns subscribe \
    --topic-arn "$TOPIC_ARN" \
    --protocol "email" \
    --notification-endpoint "tu-email@ejemplo.com"

# Actualizar el parámetro en Parameter Store con el ARN real
aws ssm put-parameter \
    --name "/s3-scanner/sns-topic-arn" \
    --value "$TOPIC_ARN" \
    --type "String" \
    --description "ARN del tópico SNS para alertas de seguridad" \
    --overwrite
```

**IMPORTANTE**: Revisa tu email y confirma la suscripción al tópico SNS.

## 🪣 Paso 3: Crear Bucket S3 para Reportes

```bash
# Definir nombre del bucket (debe ser único globalmente)
BUCKET_NAME="mi-bucket-reportes-seguridad-$(date +%s)"

# Crear el bucket
aws s3 mb s3://$BUCKET_NAME

# Habilitar cifrado por defecto
aws s3api put-bucket-encryption \
    --bucket "$BUCKET_NAME" \
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }'

# Habilitar versionado
aws s3api put-bucket-versioning \
    --bucket "$BUCKET_NAME" \
    --versioning-configuration Status=Enabled

# Bloquear acceso público
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Configurar política de ciclo de vida (eliminar reportes después de 30 días)
aws s3api put-bucket-lifecycle-configuration \
    --bucket "$BUCKET_NAME" \
    --lifecycle-configuration file://bucket-lifecycle.json

# Actualizar parámetro con el nombre real del bucket
aws ssm put-parameter \
    --name "/s3-scanner/reports-bucket" \
    --value "$BUCKET_NAME" \
    --type "String" \
    --description "Bucket S3 para almacenar reportes de seguridad" \
    --overwrite

echo "Bucket creado: $BUCKET_NAME"
```

### Crear archivo bucket-lifecycle.json:

```bash
cat > bucket-lifecycle.json << 'EOF'
{
    "Rules": [
        {
            "ID": "DeleteOldReports",
            "Status": "Enabled",
            "Filter": {
                "Prefix": "security-reports/"
            },
            "Expiration": {
                "Days": 30
            }
        }
    ]
}
EOF
```

## 🏗️ Paso 4: Crear Repositorio ECR

```bash
# Crear repositorio ECR
REPO_URI=$(aws ecr create-repository \
    --repository-name "s3-security-scanner" \
    --image-scanning-configuration scanOnPush=true \
    --query "repository.repositoryUri" \
    --output text)

echo "Repositorio ECR creado: $REPO_URI"

# Configurar política de ciclo de vida para el repositorio
aws ecr put-lifecycle-policy \
    --repository-name "s3-security-scanner" \
    --lifecycle-policy-text '{
        "rules": [
            {
                "rulePriority": 1,
                "description": "Keep last 5 images",
                "selection": {
                    "tagStatus": "any",
                    "countType": "imageCountMoreThan",
                    "countNumber": 5
                },
                "action": {
                    "type": "expire"
                }
            }
        ]
    }'
```

## 🐳 Paso 5: Construir y Subir Imagen Docker

```bash
# Construir la imagen
docker build -t s3-security-scanner .

# Etiquetar para ECR
docker tag s3-security-scanner:latest $REPO_URI:latest

# Login a ECR
aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin $REPO_URI

# Subir imagen
docker push $REPO_URI:latest

echo "Imagen subida exitosamente a: $REPO_URI:latest"
```

## 👤 Paso 6: Crear Rol IAM para Lambda

```bash
# Crear archivo de política de confianza
cat > trust-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

# Crear el rol IAM
aws iam create-role \
    --role-name "s3-security-scanner-lambda-role" \
    --assume-role-policy-document file://trust-policy.json

# Adjuntar política básica de Lambda
aws iam attach-role-policy \
    --role-name "s3-security-scanner-lambda-role" \
    --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

# Crear política personalizada para el escáner
cat > scanner-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetLifecycleConfiguration",
                "s3:GetBucketCors"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::BUCKET_NAME",
                "arn:aws:s3:::BUCKET_NAME/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "SNS_TOPIC_ARN"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:GetParameters"
            ],
            "Resource": [
                "arn:aws:ssm:*:*:parameter/s3-scanner/*"
            ]
        }
    ]
}
EOF

# Reemplazar placeholders en la política
sed -i "s|BUCKET_NAME|$BUCKET_NAME|g" scanner-policy.json
sed -i "s|SNS_TOPIC_ARN|$TOPIC_ARN|g" scanner-policy.json

# Crear y adjuntar la política personalizada
aws iam create-policy \
    --policy-name "S3SecurityScannerPolicy" \
    --policy-document file://scanner-policy.json

# Obtener ARN de la cuenta
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Adjuntar la política al rol
aws iam attach-role-policy \
    --role-name "s3-security-scanner-lambda-role" \
    --policy-arn "arn:aws:iam::$ACCOUNT_ID:policy/S3SecurityScannerPolicy"
```

## ⚡ Paso 7: Crear Función Lambda

```bash
# Esperar a que el rol se propague
echo "Esperando propagación del rol IAM..."
sleep 30

# Crear función Lambda con contenedor
aws lambda create-function \
    --function-name "s3-security-scanner" \
    --role "arn:aws:iam::$ACCOUNT_ID:role/s3-security-scanner-lambda-role" \
    --code ImageUri=$REPO_URI:latest \
    --package-type Image \
    --timeout 900 \
    --memory-size 512 \
    --description "Escáner de seguridad para buckets S3"

echo "Función Lambda creada exitosamente"
```

## 📅 Paso 8: Configurar Programación con EventBridge

```bash
# Crear regla de EventBridge
aws events put-rule \
    --name "s3-security-scanner-schedule" \
    --schedule-expression "rate(1 day)" \
    --description "Ejecutar escáner de seguridad S3 diariamente" \
    --state ENABLED

# Obtener ARN de la función Lambda
LAMBDA_ARN=$(aws lambda get-function \
    --function-name "s3-security-scanner" \
    --query "Configuration.FunctionArn" \
    --output text)

# Agregar la función Lambda como objetivo de la regla
aws events put-targets \
    --rule "s3-security-scanner-schedule" \
    --targets "Id"="1","Arn"="$LAMBDA_ARN"

# Dar permiso a EventBridge para invocar la función Lambda
aws lambda add-permission \
    --function-name "s3-security-scanner" \
    --statement-id "allow-eventbridge" \
    --action "lambda:InvokeFunction" \
    --principal "events.amazonaws.com" \
    --source-arn "arn:aws:events:us-east-1:$ACCOUNT_ID:rule/s3-security-scanner-schedule"

echo "Programación configurada exitosamente"
```

## 📊 Paso 9: Crear Grupo de Logs

```bash
# Crear grupo de logs para la función Lambda
aws logs create-log-group \
    --log-group-name "/aws/lambda/s3-security-scanner" \
    --retention-in-days 14

echo "Grupo de logs creado"
```

## 🧪 Paso 10: Probar la Configuración

### Probar la función Lambda:

```bash
# Ejecutar prueba manual
aws lambda invoke \
    --function-name "s3-security-scanner" \
    --payload '{"test_mode": true}' \
    response.json

# Ver resultado
cat response.json | jq '.'

# Ver logs
aws logs tail /aws/lambda/s3-security-scanner --follow
```

### Probar notificaciones SNS:

```bash
# Probar notificación manual
aws lambda invoke \
    --function-name "s3-security-scanner" \
    --payload '{"test_notification": true}' \
    test-response.json
```

## 🔄 Paso 11: Actualización de Código (Para futuras actualizaciones)

Cuando necesites actualizar el código:

```bash
# 1. Reconstruir imagen
docker build -t s3-security-scanner .
docker tag s3-security-scanner:latest $REPO_URI:latest

# 2. Subir nueva imagen
aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin $REPO_URI
docker push $REPO_URI:latest

# 3. Actualizar función Lambda
aws lambda update-function-code \
    --function-name "s3-security-scanner" \
    --image-uri $REPO_URI:latest

# 4. Esperar a que se actualice
aws lambda wait function-updated \
    --function-name "s3-security-scanner"

echo "Función actualizada exitosamente"
```

## 🧹 Limpieza de Archivos Temporales

```bash
rm -f trust-policy.json scanner-policy.json bucket-lifecycle.json response.json test-response.json
```

## 📝 Verificación Final

### Verificar que todos los recursos fueron creados:

```bash
echo "=== VERIFICACIÓN DE RECURSOS ==="

echo "1. Parámetros en Parameter Store:"
aws ssm get-parameters \
    --names "/s3-scanner/reports-bucket" "/s3-scanner/sns-topic-arn" "/s3-scanner/aws-region" \
    --query "Parameters[*].[Name,Value]" \
    --output table

echo -e "\n2. Bucket S3:"
aws s3 ls | grep "$(aws ssm get-parameter --name '/s3-scanner/reports-bucket' --query 'Parameter.Value' --output text)"

echo -e "\n3. Tópico SNS:"
aws sns list-topics --query "Topics[?contains(TopicArn, 's3-security-alerts')]"

echo -e "\n4. Repositorio ECR:"
aws ecr describe-repositories --repository-names "s3-security-scanner"

echo -e "\n5. Función Lambda:"
aws lambda get-function --function-name "s3-security-scanner" --query "Configuration.[FunctionName,State,LastModified]"

echo -e "\n6. Regla de EventBridge:"
aws events describe-rule --name "s3-security-scanner-schedule"

echo -e "\n=== CONFIGURACIÓN COMPLETADA ==="
```

## 🛠️ Modificación de Parámetros

Para cambiar la configuración posteriormente:

```bash
# Cambiar bucket de reportes
aws ssm put-parameter \
    --name "/s3-scanner/reports-bucket" \
    --value "nuevo-bucket-nombre" \
    --overwrite

# Cambiar región
aws ssm put-parameter \
    --name "/s3-scanner/aws-region" \
    --value "eu-west-1" \
    --overwrite

# Ver parámetros actuales
aws ssm get-parameters \
    --names "/s3-scanner/reports-bucket" "/s3-scanner/sns-topic-arn" "/s3-scanner/aws-region" \
    --query "Parameters[*].[Name,Value]" \
    --output table
```

## 🗑️ Eliminación Completa de Recursos

Si necesitas eliminar todo el proyecto:

```bash
# Ver script de eliminación en el archivo CLEANUP.md
```

---

¡Listo! Tu S3 Security Scanner está desplegado y configurado para usar AWS Parameter Store. El sistema se ejecutará automáticamente según la programación configurada y enviará notificaciones por email cuando encuentre vulnerabilidades críticas.