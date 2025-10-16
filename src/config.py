import os
import boto3
import logging
from enum import Enum
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class ParameterStoreConfig:
    """Clase para manejar configuración desde AWS Parameter Store"""
    
    def __init__(self, aws_region: str = None):
        self.aws_region = aws_region or os.environ.get('AWS_REGION', 'us-east-1')
        self.ssm_client = boto3.client('ssm', region_name=self.aws_region)
        self._cache = {}  # Cache para evitar múltiples llamadas al Parameter Store
    
    def get_parameter(self, parameter_name: str, default_value: str = '', encrypted: bool = False) -> str:
        """Obtiene un parámetro del Parameter Store con cache"""
        
        # Verificar cache primero
        if parameter_name in self._cache:
            return self._cache[parameter_name]
        
        try:
            response = self.ssm_client.get_parameter(
                Name=parameter_name,
                WithDecryption=encrypted
            )
            value = response['Parameter']['Value']
            self._cache[parameter_name] = value
            logger.debug(f"Parámetro obtenido desde Parameter Store: {parameter_name}")
            return value
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ParameterNotFound':
                logger.warning(f"Parámetro no encontrado en Parameter Store: {parameter_name}. Usando valor por defecto: {default_value}")
            else:
                logger.error(f"Error obteniendo parámetro {parameter_name}: {str(e)}. Usando valor por defecto: {default_value}")
            
            # Cachear el valor por defecto también
            self._cache[parameter_name] = default_value
            return default_value
    
    def get_parameters_batch(self, parameter_names: list) -> Dict[str, str]:
        """Obtiene múltiples parámetros en una sola llamada para mejor rendimiento"""
        
        # Filtrar parámetros que no están en cache
        uncached_params = [name for name in parameter_names if name not in self._cache]
        
        if uncached_params:
            try:
                response = self.ssm_client.get_parameters(
                    Names=uncached_params,
                    WithDecryption=True
                )
                
                # Cachear parámetros obtenidos exitosamente
                for param in response['Parameters']:
                    self._cache[param['Name']] = param['Value']
                
                # Log parámetros no encontrados
                if response['InvalidParameters']:
                    logger.warning(f"Parámetros no encontrados: {response['InvalidParameters']}")
                    
            except ClientError as e:
                logger.error(f"Error obteniendo parámetros en lote: {str(e)}")
        
        # Retornar todos los valores desde el cache
        return {name: self._cache.get(name, '') for name in parameter_names}

class VulnerabilityLevel(Enum):
    ALTO = "ALTO"
    MEDIO = "MEDIO"
    BAJO = "BAJO"

class Config:
    """Configuración principal del proyecto usando AWS Parameter Store"""
    
    # Parámetros en Parameter Store
    PARAMETER_STORE_PREFIX = '/s3-scanner/'
    
    # Nombres de parámetros
    REPORTS_BUCKET_PARAM = f'{PARAMETER_STORE_PREFIX}reports-bucket'
    SNS_TOPIC_ARN_PARAM = f'{PARAMETER_STORE_PREFIX}sns-topic-arn'
    AWS_REGION_PARAM = f'{PARAMETER_STORE_PREFIX}aws-region'
    
    def __init__(self, aws_region: str = None):
        # Inicializar Parameter Store config
        self._param_store = ParameterStoreConfig(aws_region)
        
        # Obtener configuración desde Parameter Store
        self._load_configuration()
    
    def _load_configuration(self):
        """Carga la configuración desde Parameter Store"""
        logger.info("Cargando configuración desde AWS Parameter Store...")
        
        # Obtener parámetros en lote para mejor rendimiento
        parameter_names = [
            self.REPORTS_BUCKET_PARAM,
            self.SNS_TOPIC_ARN_PARAM,
            self.AWS_REGION_PARAM
        ]
        
        params = self._param_store.get_parameters_batch(parameter_names)
        
        # Asignar valores con fallbacks (sin llamadas redundantes)
        self.REPORTS_BUCKET = params.get(self.REPORTS_BUCKET_PARAM) or 'security-reports-bucket'
        self.SNS_TOPIC_ARN = params.get(self.SNS_TOPIC_ARN_PARAM) or ''
        self.AWS_REGION = params.get(self.AWS_REGION_PARAM) or os.environ.get('AWS_REGION', 'us-east-1')
        
        # Si algún parámetro no se obtuvo en lote, obtenerlo individualmente con fallback
        if not self.REPORTS_BUCKET or self.REPORTS_BUCKET == '':
            self.REPORTS_BUCKET = self._param_store.get_parameter(
                self.REPORTS_BUCKET_PARAM, 'security-reports-bucket'
            )
        
        if not self.SNS_TOPIC_ARN:
            self.SNS_TOPIC_ARN = self._param_store.get_parameter(
                self.SNS_TOPIC_ARN_PARAM, ''
            )
        
        if not self.AWS_REGION or self.AWS_REGION == '':
            self.AWS_REGION = self._param_store.get_parameter(
                self.AWS_REGION_PARAM, os.environ.get('AWS_REGION', 'us-east-1')
            )
        
        logger.info(f"Configuración cargada - Bucket: {self.REPORTS_BUCKET}, Región: {self.AWS_REGION}")
        
        # Configurar constantes
        self.REPORT_FORMATS = ['json', 'csv', 'html']
        self.DATE_FORMAT = '%Y-%m-%d_%H-%M-%S'
        
        # Configuración de vulnerabilidades (estas permanecen estáticas)
        self.VULNERABILITY_RULES: Dict[str, Dict[str, Any]] = {
            'public_read_acp': {
                'level': VulnerabilityLevel.ALTO,
                'description': 'Bucket con permisos de lectura públicos en ACL'
            },
            'public_write_acp': {
                'level': VulnerabilityLevel.ALTO,
                'description': 'Bucket con permisos de escritura públicos en ACL'
            },
            'public_read_policy': {
                'level': VulnerabilityLevel.ALTO,
                'description': 'Bucket con política que permite lectura pública'
            },
            'public_write_policy': {
                'level': VulnerabilityLevel.ALTO,
                'description': 'Bucket con política que permite escritura pública'
            },
            'no_encryption': {
                'level': VulnerabilityLevel.ALTO,
                'description': 'Bucket sin cifrado configurado'
            },
            'versioning_disabled': {
                'level': VulnerabilityLevel.MEDIO,
                'description': 'Versionado deshabilitado'
            },
            'no_access_logging': {
                'level': VulnerabilityLevel.MEDIO,
                'description': 'Logging de acceso no configurado'
            },
            'no_mfa_delete': {
                'level': VulnerabilityLevel.MEDIO,
                'description': 'MFA Delete no habilitado'
            },
            'no_lifecycle_policy': {
                'level': VulnerabilityLevel.BAJO,
                'description': 'No tiene política de ciclo de vida configurada'
            },
            'no_cors_configuration': {
                'level': VulnerabilityLevel.BAJO,
                'description': 'Configuración CORS no definida'
            },
            'default_encryption_sse_s3': {
                'level': VulnerabilityLevel.BAJO,
                'description': 'Usando cifrado SSE-S3 en lugar de SSE-KMS'
            }
        }
