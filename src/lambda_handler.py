import json
import logging
import tempfile
import os
from datetime import datetime
from typing import Dict, Any

from config import Config
from s3_scanner import S3SecurityScanner
from reporting import ReportGenerator
from s3_uploader import S3ReportUploader
from notifications import SNSNotifier

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handler principal de Lambda para el escaneo de seguridad S3
    
    Args:
        event: Evento de Lambda (puede contener configuraciones específicas)
        context: Contexto de Lambda
        
    Returns:
        Diccionario con resultados del proceso
    """
    
    start_time = datetime.utcnow()
    execution_summary = {
        'start_time': start_time.isoformat(),
        'status': 'started',
        'scan_results': None,
        'reports_uploaded': {},
        'notification_sent': False,
        'errors': []
    }
    
    logger.info("Iniciando escaneo de seguridad S3")
    
    try:
        # Inicializar configuración una sola vez y compartirla
        config = Config()
        
        # 1. Escanear buckets S3
        logger.info("Paso 1: Escaneando buckets S3...")
        scanner = S3SecurityScanner(config=config)
        scan_results = scanner.scan_all_buckets()
        execution_summary['scan_results'] = scan_results
        
        logger.info(f"Escaneo completado. Buckets escaneados: {scan_results['scan_metadata']['scanned_buckets']}")
        logger.info(f"Vulnerabilidades encontradas: {scan_results['scan_metadata']['total_vulnerabilities']} "
                   f"(ALTO: {scan_results['scan_metadata']['high_severity']}, "
                   f"MEDIO: {scan_results['scan_metadata']['medium_severity']}, "
                   f"BAJO: {scan_results['scan_metadata']['low_severity']})")
        
        # 2. Generar reportes
        logger.info("Paso 2: Generando reportes...")
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(temp_dir, config=config)
            local_report_paths = report_generator.save_reports(scan_results)
            
            logger.info(f"Reportes generados en: {list(local_report_paths.keys())}")
            
            # 3. Subir reportes a S3
            logger.info("Paso 3: Subiendo reportes a S3...")
            uploader = S3ReportUploader(config=config)
            
            # Verificar acceso al bucket
            if not uploader.verify_bucket_access():
                raise Exception(f"No se puede acceder al bucket de reportes: {config.REPORTS_BUCKET}")
            
            # Obtener timestamp del directorio generado
            report_timestamp = os.path.basename(list(local_report_paths.values())[0]).split('/')[0]
            if not report_timestamp:
                report_timestamp = datetime.utcnow().strftime(config.DATE_FORMAT)
            
            s3_urls = uploader.upload_reports(local_report_paths, report_timestamp)
            execution_summary['reports_uploaded'] = s3_urls
            
            logger.info(f"Reportes subidos a S3: {s3_urls}")
            
            # Limpiar archivos temporales (se hace automáticamente al salir del context manager)
        
        # 4. Verificar si se necesita enviar notificación
        logger.info("Paso 4: Verificando necesidad de notificaciones...")
        notifier = SNSNotifier(config=config)
        notification_sent = notifier.check_and_notify(scan_results)
        execution_summary['notification_sent'] = notification_sent
        
        if notification_sent:
            logger.info("Notificación SNS enviada por vulnerabilidades de nivel ALTO")
        else:
            logger.info("No se envió notificación (sin vulnerabilidades ALTO o SNS no configurado)")
        
        # 5. Limpieza opcional de reportes antiguos
        cleanup_enabled = event.get('cleanup_old_reports', True)
        cleanup_days = event.get('cleanup_days', 30)
        
        if cleanup_enabled:
            logger.info(f"Paso 5: Limpiando reportes antiguos (> {cleanup_days} días)...")
            deleted_count = uploader.cleanup_old_reports(cleanup_days)
            execution_summary['old_reports_cleaned'] = deleted_count
        
        # Finalizar con éxito
        end_time = datetime.utcnow()
        execution_summary.update({
            'status': 'completed',
            'end_time': end_time.isoformat(),
            'duration_seconds': (end_time - start_time).total_seconds()
        })
        
        logger.info(f"Proceso completado exitosamente en {execution_summary['duration_seconds']:.2f} segundos")
        
        return {
            'statusCode': 200,
            'body': json.dumps(execution_summary, ensure_ascii=False, indent=2)
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error durante la ejecución: {error_msg}")
        
        end_time = datetime.utcnow()
        execution_summary.update({
            'status': 'failed',
            'end_time': end_time.isoformat(),
            'duration_seconds': (end_time - start_time).total_seconds(),
            'errors': [error_msg]
        })
        
        # Intentar enviar notificación de error crítico si SNS está configurado
        try:
            error_config = Config()  # Nueva instancia para manejo de errores
            if error_config.SNS_TOPIC_ARN:
                error_notifier = SNSNotifier(config=error_config)
                if error_notifier.sns_client:
                    error_notifier.sns_client.publish(
                        TopicArn=error_config.SNS_TOPIC_ARN,
                        Subject="ERROR CRÍTICO: Fallo en escaneo de seguridad S3",
                        Message=f"El escaneo de seguridad S3 falló con el siguiente error:\n\n{error_msg}\n\nRevise los logs de Lambda para más detalles.",
                        MessageStructure='string'
                    )
                    logger.info("Notificación de error enviada")
        except Exception as notify_error:
            logger.error(f"Error adicional enviando notificación de fallo: {str(notify_error)}")
        
        return {
            'statusCode': 500,
            'body': json.dumps(execution_summary, ensure_ascii=False, indent=2)
        }

def test_handler(event: Dict[str, Any] = None, context: Any = None) -> Dict[str, Any]:
    """
    Función auxiliar para probar el handler localmente
    """
    if event is None:
        event = {
            'cleanup_old_reports': False,  # Deshabilitado por defecto en pruebas
            'test_mode': True
        }
    
    # Mock del contexto si no se proporciona
    if context is None:
        class MockContext:
            def __init__(self):
                self.function_name = "s3-security-scanner-test"
                self.function_version = "$LATEST"
                self.memory_limit_in_mb = 512
                self.remaining_time_in_millis = lambda: 300000  # 5 minutos
        
        context = MockContext()
    
    return handler(event, context)

# Función de prueba de notificaciones
def test_notifications() -> bool:
    """
    Función auxiliar para probar las notificaciones SNS
    """
    try:
        config = Config()
        notifier = SNSNotifier(config=config)
        return notifier.send_test_notification()
    except Exception as e:
        logger.error(f"Error en prueba de notificaciones: {str(e)}")
        return False

if __name__ == "__main__":
    # Ejecución local para pruebas
    logger.info("Ejecutando escaneo de seguridad S3 en modo local")
    
    # Verificar variables de entorno básicas
    required_vars = ['REPORTS_BUCKET']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        logger.warning(f"Variables de entorno faltantes: {missing_vars}")
        logger.info("Configurando valores por defecto para prueba local")
        os.environ.setdefault('REPORTS_BUCKET', 'test-security-reports-bucket')
        os.environ.setdefault('AWS_REGION', 'us-east-1')
    
    # Ejecutar prueba
    result = test_handler()
    
    print("\n" + "="*50)
    print("RESULTADO DE LA EJECUCIÓN:")
    print("="*50)
    print(json.dumps(result, ensure_ascii=False, indent=2))