import boto3
import os
import logging
from typing import Dict, List
from botocore.exceptions import ClientError
from config import Config

logger = logging.getLogger(__name__)

class S3ReportUploader:
    def __init__(self, config: Config = None, bucket_name: str = None, aws_region: str = None):
        # Usar configuración proporcionada o crear nueva instancia
        self.config = config or Config(aws_region)
        self.bucket_name = bucket_name or self.config.REPORTS_BUCKET
        self.aws_region = aws_region or self.config.AWS_REGION
        self.s3_client = boto3.client('s3', region_name=self.aws_region)
    
    def upload_reports(self, local_report_paths: Dict[str, str], report_timestamp: str) -> Dict[str, str]:
        """
        Sube los reportes al bucket S3
        
        Args:
            local_report_paths: Dict con paths locales de reportes {'json': '/path/to/report.json', ...}
            report_timestamp: Timestamp del reporte para organizar en S3
            
        Returns:
            Dict con las URLs de S3 de los reportes subidos
        """
        s3_urls = {}
        
        for format_type, local_path in local_report_paths.items():
            try:
                # Crear key de S3 con estructura organizada por fecha
                s3_key = f"security-reports/{report_timestamp}/report.{format_type}"
                
                # Subir archivo
                self.s3_client.upload_file(
                    local_path,
                    self.bucket_name,
                    s3_key,
                    ExtraArgs={
                        'ServerSideEncryption': 'AES256',
                        'ContentType': self._get_content_type(format_type)
                    }
                )
                
                # Generar URL de S3
                s3_url = f"s3://{self.bucket_name}/{s3_key}"
                s3_urls[format_type] = s3_url
                
                logger.info(f"Reporte {format_type} subido exitosamente a {s3_url}")
                
            except ClientError as e:
                logger.error(f"Error subiendo reporte {format_type} a S3: {str(e)}")
                s3_urls[format_type] = f"ERROR: {str(e)}"
            except FileNotFoundError:
                logger.error(f"Archivo local no encontrado: {local_path}")
                s3_urls[format_type] = f"ERROR: Archivo local no encontrado"
        
        return s3_urls
    
    def _get_content_type(self, format_type: str) -> str:
        """Obtiene el Content-Type apropiado para cada formato de reporte"""
        content_types = {
            'json': 'application/json',
            'csv': 'text/csv',
            'html': 'text/html'
        }
        return content_types.get(format_type, 'text/plain')
    
    def verify_bucket_access(self) -> bool:
        """Verifica que se puede acceder al bucket de reportes"""
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            logger.info(f"Acceso al bucket {self.bucket_name} verificado exitosamente")
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                logger.error(f"El bucket {self.bucket_name} no existe")
            elif error_code == '403':
                logger.error(f"Sin permisos para acceder al bucket {self.bucket_name}")
            else:
                logger.error(f"Error verificando acceso al bucket {self.bucket_name}: {str(e)}")
            return False
    
    def cleanup_local_files(self, file_paths: Dict[str, str]) -> None:
        """Limpia archivos locales después de subirlos a S3"""
        for format_type, file_path in file_paths.items():
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.debug(f"Archivo local {format_type} eliminado: {file_path}")
            except OSError as e:
                logger.warning(f"Error eliminando archivo local {file_path}: {str(e)}")
    
    def cleanup_old_reports(self, days_to_keep: int = 30) -> int:
        """
        Elimina reportes antiguos del bucket S3
        
        Args:
            days_to_keep: Número de días de reportes a mantener
            
        Returns:
            Número de objetos eliminados
        """
        try:
            from datetime import datetime, timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            # Listar objetos en el prefijo de reportes
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket_name, Prefix='security-reports/')
            
            objects_to_delete = []
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                    
                for obj in page['Contents']:
                    if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                        objects_to_delete.append({'Key': obj['Key']})
            
            if not objects_to_delete:
                logger.info("No se encontraron reportes antiguos para eliminar")
                return 0
            
            # Eliminar objetos en lotes
            deleted_count = 0
            batch_size = 1000  # Máximo permitido por delete_objects
            
            for i in range(0, len(objects_to_delete), batch_size):
                batch = objects_to_delete[i:i + batch_size]
                
                response = self.s3_client.delete_objects(
                    Bucket=self.bucket_name,
                    Delete={'Objects': batch}
                )
                
                deleted_count += len(response.get('Deleted', []))
                
                # Log errores si los hay
                for error in response.get('Errors', []):
                    logger.error(f"Error eliminando {error['Key']}: {error['Message']}")
            
            logger.info(f"Se eliminaron {deleted_count} reportes antiguos (> {days_to_keep} días)")
            return deleted_count
            
        except ClientError as e:
            logger.error(f"Error limpiando reportes antiguos: {str(e)}")
            return 0