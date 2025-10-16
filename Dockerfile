FROM public.ecr.aws/lambda/python:3.11

# Copiar archivos de dependencias
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# Instalar dependencias
RUN pip install -r requirements.txt

# Copiar código fuente
COPY src/ ${LAMBDA_TASK_ROOT}

# Comando para ejecutar la función Lambda
CMD ["lambda_handler.handler"]