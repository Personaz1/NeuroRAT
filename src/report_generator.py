import json
import os

class ReportGenerator:
    """Генератор отчетов для VulnerabilityScanner"""
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate(self, results):
        """Генерирует JSON-отчет и возвращает путь к файлу"""
        file_path = os.path.join(self.output_dir, 'report.json')
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
        return file_path 