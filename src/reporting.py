import csv
import json
import os
from datetime import datetime
from typing import Dict, Any, List
from jinja2 import Environment, BaseLoader
from config import Config

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8" />
    <title>Reporte de Seguridad S3 - {{ timestamp }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .ALTO { color: #b30000; font-weight: bold; }
        .MEDIO { color: #cc7a00; font-weight: bold; }
        .BAJO { color: #2d862d; font-weight: bold; }
        .meta { margin-bottom: 20px; }
        .meta div { margin: 4px 0; }
        .bucket { margin-bottom: 30px; }
        .small { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Reporte de Seguridad S3</h1>
    <div class="meta">
        <div><strong>Fecha:</strong> {{ timestamp }}</div>
        <div><strong>Total de buckets:</strong> {{ scan_metadata.total_buckets }}</div>
        <div><strong>Escaneados:</strong> {{ scan_metadata.scanned_buckets }}</div>
        <div><strong>Fallidos:</strong> {{ scan_metadata.failed_scans }}</div>
        <div><strong>Vulnerabilidades:</strong> Total {{ scan_metadata.total_vulnerabilities }} | 
            <span class="ALTO">ALTO {{ scan_metadata.high_severity }}</span> |
            <span class="MEDIO">MEDIO {{ scan_metadata.medium_severity }}</span> |
            <span class="BAJO">BAJO {{ scan_metadata.low_severity }}</span>
        </div>
    </div>

    {% for bucket in buckets %}
    <div class="bucket">
        <h2>Bucket: {{ bucket.bucket_name }} <span class="small">(Región: {{ bucket.region }})</span></h2>
        {% if bucket.scan_status != 'completed' %}
            <div class="ALTO">Escaneo fallido: {{ bucket.error }}</div>
        {% else %}
            {% if bucket.vulnerabilities|length == 0 %}
                <div>No se encontraron vulnerabilidades.</div>
            {% else %}
                <table>
                    <thead>
                        <tr>
                            <th>Nivel</th>
                            <th>Tipo</th>
                            <th>Descripción</th>
                            <th>Detalles</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for v in bucket.vulnerabilities %}
                        <tr>
                            <td class="{{ v.level }}">{{ v.level }}</td>
                            <td>{{ v.type }}</td>
                            <td>{{ v.description }}</td>
                            <td>{{ v.details }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% endif %}
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>
"""

class ReportGenerator:
    def __init__(self, base_dir: str, config: Config = None):
        self.base_dir = base_dir
        # Usar configuración proporcionada o crear nueva instancia
        self.config = config or Config()

    def _ensure_dir(self, dir_path: str):
        os.makedirs(dir_path, exist_ok=True)

    def save_reports(self, scan_results: Dict[str, Any]) -> Dict[str, str]:
        timestamp = datetime.utcnow().strftime(self.config.DATE_FORMAT)
        output_dir = os.path.join(self.base_dir, timestamp)
        self._ensure_dir(output_dir)

        paths = {}
        # JSON
        json_path = os.path.join(output_dir, 'report.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, ensure_ascii=False, indent=2)
        paths['json'] = json_path

        # CSV
        csv_path = os.path.join(output_dir, 'report.csv')
        self._write_csv(csv_path, scan_results)
        paths['csv'] = csv_path

        # HTML
        html_path = os.path.join(output_dir, 'report.html')
        self._write_html(html_path, scan_results, timestamp)
        paths['html'] = html_path

        return paths

    def _write_csv(self, path: str, scan_results: Dict[str, Any]):
        with open(path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['bucket_name', 'region', 'level', 'type', 'description', 'details'])
            for bucket in scan_results.get('buckets', []):
                if bucket.get('scan_status') != 'completed':
                    writer.writerow([bucket.get('bucket_name'), bucket.get('region'), 'ALTO', 'scan_failed', 'Escaneo fallido', bucket.get('error')])
                    continue
                vulns: List[Dict[str, Any]] = bucket.get('vulnerabilities', [])
                if not vulns:
                    writer.writerow([bucket.get('bucket_name'), bucket.get('region'), '', 'none', 'Sin vulnerabilidades', ''])
                for v in vulns:
                    writer.writerow([
                        bucket.get('bucket_name'),
                        bucket.get('region'),
                        v.get('level'),
                        v.get('type'),
                        v.get('description'),
                        v.get('details')
                    ])

    def _write_html(self, path: str, scan_results: Dict[str, Any], timestamp: str):
        env = Environment(loader=BaseLoader())
        template = env.from_string(HTML_TEMPLATE)
        html_content = template.render(
            timestamp=timestamp,
            scan_metadata=scan_results.get('scan_metadata', {}),
            buckets=scan_results.get('buckets', [])
        )
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
