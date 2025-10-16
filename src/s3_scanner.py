import boto3
import json
import logging
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError
from config import Config, VulnerabilityLevel

logger = logging.getLogger(__name__)

class S3SecurityScanner:
    def __init__(self, config: Config = None, aws_region: str = None):
        # Usar configuración proporcionada o crear nueva instancia
        self.config = config or Config(aws_region)
        self.aws_region = aws_region or self.config.AWS_REGION
        try:
            self.s3_client = boto3.client('s3', region_name=self.aws_region)
            self.s3_resource = boto3.resource('s3', region_name=self.aws_region)
        except NoCredentialsError:
            logger.error("No se encontraron credenciales de AWS")
            raise
    
    def scan_all_buckets(self) -> Dict[str, Any]:
        """Escanea todos los buckets S3 en la cuenta"""
        scan_results = {
            'scan_metadata': {
                'total_buckets': 0,
                'scanned_buckets': 0,
                'failed_scans': 0,
                'total_vulnerabilities': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0
            },
            'buckets': []
        }
        
        try:
            # Listar todos los buckets
            response = self.s3_client.list_buckets()
            buckets = response['Buckets']
            scan_results['scan_metadata']['total_buckets'] = len(buckets)
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                logger.info(f"Escaneando bucket: {bucket_name}")
                
                try:
                    bucket_result = self.scan_bucket(bucket_name)
                    scan_results['buckets'].append(bucket_result)
                    scan_results['scan_metadata']['scanned_buckets'] += 1
                    
                    # Contar vulnerabilidades por nivel
                    for vuln in bucket_result['vulnerabilities']:
                        scan_results['scan_metadata']['total_vulnerabilities'] += 1
                        if vuln['level'] == VulnerabilityLevel.ALTO.value:
                            scan_results['scan_metadata']['high_severity'] += 1
                        elif vuln['level'] == VulnerabilityLevel.MEDIO.value:
                            scan_results['scan_metadata']['medium_severity'] += 1
                        elif vuln['level'] == VulnerabilityLevel.BAJO.value:
                            scan_results['scan_metadata']['low_severity'] += 1
                            
                except Exception as e:
                    logger.error(f"Error escaneando bucket {bucket_name}: {str(e)}")
                    scan_results['scan_metadata']['failed_scans'] += 1
                    scan_results['buckets'].append({
                        'bucket_name': bucket_name,
                        'scan_status': 'failed',
                        'error': str(e),
                        'vulnerabilities': []
                    })
            
            return scan_results
            
        except ClientError as e:
            logger.error(f"Error listando buckets: {str(e)}")
            raise
    
    def scan_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """Escanea un bucket específico para vulnerabilidades de seguridad"""
        bucket_result = {
            'bucket_name': bucket_name,
            'scan_status': 'completed',
            'region': self._get_bucket_region(bucket_name),
            'vulnerabilities': []
        }
        
        # Lista de verificaciones de seguridad
        security_checks = [
            self._check_bucket_acl,
            self._check_bucket_policy,
            self._check_encryption,
            self._check_versioning,
            self._check_access_logging,
            self._check_lifecycle_policy,
            self._check_cors_configuration
        ]
        
        for check in security_checks:
            try:
                vulnerabilities = check(bucket_name)
                bucket_result['vulnerabilities'].extend(vulnerabilities)
            except Exception as e:
                logger.warning(f"Error en verificación para {bucket_name}: {str(e)}")
        
        return bucket_result
    
    def _get_bucket_region(self, bucket_name: str) -> str:
        """Obtiene la región del bucket"""
        try:
            response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            region = response.get('LocationConstraint')
            return region if region else 'us-east-1'
        except ClientError:
            return 'unknown'
    
    def _check_bucket_acl(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Verifica permisos públicos en ACL del bucket"""
        vulnerabilities = []
        
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = response.get('Grants', [])
            
            for grant in grants:
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission')
                
                # Verificar permisos públicos
                if grantee.get('Type') == 'Group':
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        if permission in ['READ', 'READ_ACP']:
                            vulnerabilities.append(self._create_vulnerability(
                                'public_read_acp',
                                f"Permiso {permission} otorgado a {uri}"
                            ))
                        elif permission in ['WRITE', 'WRITE_ACP', 'FULL_CONTROL']:
                            vulnerabilities.append(self._create_vulnerability(
                                'public_write_acp',
                                f"Permiso {permission} otorgado a {uri}"
                            ))
            
        except ClientError as e:
            logger.warning(f"Error verificando ACL para {bucket_name}: {str(e)}")
        
        return vulnerabilities
    
    def _check_bucket_policy(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Verifica política del bucket para permisos públicos"""
        vulnerabilities = []
        
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response['Policy'])
            
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal')
                effect = statement.get('Effect')
                action = statement.get('Action', [])
                
                # Verificar políticas públicas
                if effect == 'Allow' and (principal == '*' or 
                    (isinstance(principal, dict) and principal.get('AWS') == '*')):
                    
                    if isinstance(action, str):
                        action = [action]
                    
                    read_actions = ['s3:GetObject', 's3:GetBucketLocation', 's3:ListBucket']
                    write_actions = ['s3:PutObject', 's3:DeleteObject', 's3:PutBucketPolicy']
                    
                    if any(act in read_actions or act == 's3:*' for act in action):
                        vulnerabilities.append(self._create_vulnerability(
                            'public_read_policy',
                            f"Política permite acceso público de lectura: {action}"
                        ))
                    
                    if any(act in write_actions or act == 's3:*' for act in action):
                        vulnerabilities.append(self._create_vulnerability(
                            'public_write_policy',
                            f"Política permite acceso público de escritura: {action}"
                        ))
            
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                logger.warning(f"Error verificando política para {bucket_name}: {str(e)}")
        
        return vulnerabilities
    
    def _check_encryption(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Verifica configuración de cifrado del bucket"""
        vulnerabilities = []
        
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            
            if not rules:
                vulnerabilities.append(self._create_vulnerability(
                    'no_encryption',
                    "No tiene reglas de cifrado configuradas"
                ))
            else:
                # Verificar tipo de cifrado
                for rule in rules:
                    sse = rule.get('ApplyServerSideEncryptionByDefault', {})
                    if sse.get('SSEAlgorithm') == 'AES256':
                        vulnerabilities.append(self._create_vulnerability(
                            'default_encryption_sse_s3',
                            "Usando SSE-S3 en lugar de SSE-KMS para mayor seguridad"
                        ))
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                vulnerabilities.append(self._create_vulnerability(
                    'no_encryption',
                    "No tiene cifrado configurado"
                ))
            else:
                logger.warning(f"Error verificando cifrado para {bucket_name}: {str(e)}")
        
        return vulnerabilities
    
    def _check_versioning(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Verifica configuración de versionado"""
        vulnerabilities = []
        
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = response.get('Status')
            mfa_delete = response.get('MFADelete')
            
            if status != 'Enabled':
                vulnerabilities.append(self._create_vulnerability(
                    'versioning_disabled',
                    f"Versionado está {status or 'deshabilitado'}"
                ))
            
            if status == 'Enabled' and mfa_delete != 'Enabled':
                vulnerabilities.append(self._create_vulnerability(
                    'no_mfa_delete',
                    "MFA Delete no está habilitado"
                ))
            
        except ClientError as e:
            logger.warning(f"Error verificando versionado para {bucket_name}: {str(e)}")
        
        return vulnerabilities
    
    def _check_access_logging(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Verifica configuración de logging de acceso"""
        vulnerabilities = []
        
        try:
            response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            logging_config = response.get('LoggingEnabled')
            
            if not logging_config:
                vulnerabilities.append(self._create_vulnerability(
                    'no_access_logging',
                    "Logging de acceso no está configurado"
                ))
            
        except ClientError as e:
            logger.warning(f"Error verificando logging para {bucket_name}: {str(e)}")
        
        return vulnerabilities
    
    def _check_lifecycle_policy(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Verifica configuración de política de ciclo de vida"""
        vulnerabilities = []
        
        try:
            response = self.s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            rules = response.get('Rules', [])
            
            if not rules:
                vulnerabilities.append(self._create_vulnerability(
                    'no_lifecycle_policy',
                    "No tiene política de ciclo de vida configurada"
                ))
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                vulnerabilities.append(self._create_vulnerability(
                    'no_lifecycle_policy',
                    "No tiene política de ciclo de vida configurada"
                ))
            else:
                logger.warning(f"Error verificando lifecycle para {bucket_name}: {str(e)}")
        
        return vulnerabilities
    
    def _check_cors_configuration(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Verifica configuración CORS"""
        vulnerabilities = []
        
        try:
            response = self.s3_client.get_bucket_cors(Bucket=bucket_name)
            cors_rules = response.get('CORSRules', [])
            
            # Esta es una verificación básica - en un entorno real podrías querer
            # verificar configuraciones CORS específicas según tus necesidades
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchCORSConfiguration':
                vulnerabilities.append(self._create_vulnerability(
                    'no_cors_configuration',
                    "Configuración CORS no definida"
                ))
            else:
                logger.warning(f"Error verificando CORS para {bucket_name}: {str(e)}")
        
        return vulnerabilities
    
    def _create_vulnerability(self, vuln_type: str, details: str) -> Dict[str, Any]:
        """Crea un objeto de vulnerabilidad con la información correspondiente"""
        rule = self.config.VULNERABILITY_RULES.get(vuln_type, {})
        return {
            'type': vuln_type,
            'level': rule.get('level', VulnerabilityLevel.BAJO).value,
            'description': rule.get('description', 'Vulnerabilidad desconocida'),
            'details': details
        }