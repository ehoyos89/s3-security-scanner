import boto3
import json
import logging
from typing import Dict, Any, List
from botocore.exceptions import ClientError
from config import Config, VulnerabilityLevel

logger = logging.getLogger(__name__)

class SNSNotifier:
    def __init__(self, config: Config = None, topic_arn: str = None, aws_region: str = None):
        # Usar configuración proporcionada o crear nueva instancia
        self.config = config or Config(aws_region)
        self.topic_arn = topic_arn or self.config.SNS_TOPIC_ARN
        self.aws_region = aws_region or self.config.AWS_REGION
        
        if not self.topic_arn:
            logger.warning("No se configuró SNS_TOPIC_ARN - las notificaciones no se enviarán")
            self.sns_client = None
        else:
            self.sns_client = boto3.client('sns', region_name=self.aws_region)
    
    def check_and_notify(self, scan_results: Dict[str, Any]) -> bool:
        """
        Verifica si hay vulnerabilidades de nivel ALTO y envía notificación si es necesario
        Retorna True si se envió una notificación, False en caso contrario
        """
        if not self.sns_client:
            logger.info("SNS no configurado - omitiendo notificaciones")
            return False
        
        high_severity_count = scan_results.get('scan_metadata', {}).get('high_severity', 0)
        
        if high_severity_count == 0:
            logger.info("No se encontraron vulnerabilidades de nivel ALTO - no se envía notificación")
            return False
        
        # Recopilar información detallada sobre vulnerabilidades ALTO
        high_vulnerabilities = self._collect_high_severity_vulnerabilities(scan_results)
        
        # Crear mensaje de notificación
        message = self._create_notification_message(scan_results, high_vulnerabilities)
        subject = f"ALERTA: {high_severity_count} vulnerabilidades ALTO encontradas en buckets S3"
        
        try:
            response = self.sns_client.publish(
                TopicArn=self.topic_arn,
                Subject=subject,
                Message=message,
                MessageStructure='string'
            )
            
            logger.info(f"Notificación SNS enviada exitosamente. MessageId: {response['MessageId']}")
            return True
            
        except ClientError as e:
            logger.error(f"Error enviando notificación SNS: {str(e)}")
            return False
    
    def _collect_high_severity_vulnerabilities(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Recopila todas las vulnerabilidades de nivel ALTO con detalles del bucket"""
        high_vulnerabilities = []
        
        for bucket in scan_results.get('buckets', []):
            bucket_name = bucket.get('bucket_name')
            bucket_region = bucket.get('region')
            
            for vuln in bucket.get('vulnerabilities', []):
                if vuln.get('level') == VulnerabilityLevel.ALTO.value:
                    high_vulnerabilities.append({
                        'bucket_name': bucket_name,
                        'bucket_region': bucket_region,
                        'vulnerability_type': vuln.get('type'),
                        'description': vuln.get('description'),
                        'details': vuln.get('details')
                    })
        
        return high_vulnerabilities
    
    def _create_notification_message(self, scan_results: Dict[str, Any], high_vulnerabilities: List[Dict[str, Any]]) -> str:
        """Crea el mensaje de notificación con resumen y detalles"""
        metadata = scan_results.get('scan_metadata', {})
        
        message_lines = [
            "ALERTA DE SEGURIDAD - BUCKETS S3",
            "=" * 40,
            "",
            "RESUMEN DEL ESCANEO:",
            f"• Total de buckets: {metadata.get('total_buckets', 0)}",
            f"• Buckets escaneados: {metadata.get('scanned_buckets', 0)}",
            f"• Escaneos fallidos: {metadata.get('failed_scans', 0)}",
            "",
            "VULNERABILIDADES ENCONTRADAS:",
            f"• ALTO: {metadata.get('high_severity', 0)} (CRÍTICO)",
            f"• MEDIO: {metadata.get('medium_severity', 0)}",
            f"• BAJO: {metadata.get('low_severity', 0)}",
            "",
            "VULNERABILIDADES DE NIVEL ALTO DETECTADAS:",
            "=" * 45
        ]
        
        if not high_vulnerabilities:
            message_lines.append("No se encontraron vulnerabilidades de nivel ALTO.")
        else:
            # Agrupar por bucket para mejor legibilidad
            buckets_with_high_vulns = {}
            for vuln in high_vulnerabilities:
                bucket_name = vuln['bucket_name']
                if bucket_name not in buckets_with_high_vulns:
                    buckets_with_high_vulns[bucket_name] = {
                        'region': vuln['bucket_region'],
                        'vulnerabilities': []
                    }
                buckets_with_high_vulns[bucket_name]['vulnerabilities'].append(vuln)
            
            for bucket_name, bucket_info in buckets_with_high_vulns.items():
                message_lines.extend([
                    "",
                    f"BUCKET: {bucket_name} (Región: {bucket_info['region']})",
                    "-" * (len(bucket_name) + 20)
                ])
                
                for vuln in bucket_info['vulnerabilities']:
                    message_lines.extend([
                        f"• Tipo: {vuln['vulnerability_type']}",
                        f"  Descripción: {vuln['description']}",
                        f"  Detalles: {vuln['details']}",
                        ""
                    ])
        
        message_lines.extend([
            "",
            "ACCIONES RECOMENDADAS:",
            "1. Revise inmediatamente los buckets afectados",
            "2. Corrija las vulnerabilidades de nivel ALTO prioritariamente",
            "3. Implemente controles de acceso apropiados",
            "4. Considere habilitar cifrado y logging donde sea necesario",
            "",
            "Este mensaje fue generado automáticamente por el sistema de monitoreo de seguridad S3."
        ])
        
        return "\n".join(message_lines)
    
    def send_test_notification(self) -> bool:
        """Envía una notificación de prueba para verificar la configuración"""
        if not self.sns_client:
            logger.error("SNS no configurado - no se puede enviar notificación de prueba")
            return False
        
        test_message = """
NOTIFICACIÓN DE PRUEBA - Sistema de Monitoreo S3

Este es un mensaje de prueba para verificar que las notificaciones SNS 
están configuradas correctamente.

Si recibe este mensaje, la configuración es correcta.
"""
        
        try:
            response = self.sns_client.publish(
                TopicArn=self.topic_arn,
                Subject="PRUEBA: Sistema de Notificaciones S3",
                Message=test_message.strip(),
                MessageStructure='string'
            )
            
            logger.info(f"Notificación de prueba enviada. MessageId: {response['MessageId']}")
            return True
            
        except ClientError as e:
            logger.error(f"Error enviando notificación de prueba: {str(e)}")
            return False