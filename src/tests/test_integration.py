#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Интеграционные тесты для модулей ExploitAutomation и C1ExploitIntegration.

Этот скрипт тестирует интеграцию между различными модулями системы,
включая автоматизацию эксплойтов и взаимодействие с LLM-агентом.
"""

import os
import sys
import json
import unittest
import tempfile
from unittest.mock import MagicMock, patch

# Добавляем родительскую директорию в путь для импорта
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Импортируем тестируемые модули
from exploit_automation import ExploitAutomation
from c1_exploit_integration import C1ExploitIntegration

class TestExploitAutomation(unittest.TestCase):
    """Тесты для модуля автоматизации эксплойтов."""
    
    def setUp(self):
        """Настройка перед каждым тестом."""
        # Создаем экземпляр класса с безопасным режимом
        self.automation = ExploitAutomation(safe_mode=True)
        
        # Создаем заглушки для зависимостей
        self.automation.host_scanner = MagicMock()
        self.automation.port_scanner = MagicMock()
        self.automation.service_detector = MagicMock()
        self.automation.vulnerability_scanner = MagicMock()
        self.automation.exploit_engine = MagicMock()
        
        # Настраиваем заглушки
        self.automation.host_scanner.scan_network.return_value = ["192.168.1.1", "192.168.1.2"]
        self.automation.port_scanner.scan.return_value = [22, 80, 443]
        self.automation.service_detector.detect.return_value = "http"
        self.automation.vulnerability_scanner.scan.return_value = [
            {"id": "CVE-2021-1234", "description": "Test vulnerability"}
        ]
        self.automation.exploit_engine.search_exploits.return_value = [
            {"id": "EXP-1", "name": "Test Exploit"}
        ]
        self.automation.exploit_engine.run_exploit.return_value = {"success": True}
    
    def test_auto_scan(self):
        """Тестирование автоматического сканирования."""
        # Запускаем сканирование
        results = self.automation.auto_scan("192.168.1.0/24")
        
        # Проверяем, что все методы сканирования были вызваны
        self.automation.host_scanner.scan_network.assert_called_once_with("192.168.1.0/24")
        self.automation.port_scanner.scan.assert_called()
        self.automation.service_detector.detect.assert_called()
        self.automation.vulnerability_scanner.scan.assert_called()
        self.automation.exploit_engine.search_exploits.assert_called()
        
        # Проверяем результаты
        self.assertEqual(len(results["live_hosts"]), 2)
        self.assertIn("192.168.1.1", results["live_hosts"])
        self.assertIn("192.168.1.2", results["live_hosts"])
        self.assertIn("open_ports", results)
        self.assertIn("detected_services", results)
        self.assertIn("vulnerabilities", results)
        self.assertIn("exploits_to_run", results)
    
    def test_auto_exploit(self):
        """Тестирование автоматической эксплуатации."""
        # Сначала выполняем сканирование
        self.automation.auto_scan("192.168.1.0/24")
        
        # Затем выполняем эксплуатацию
        results = self.automation.auto_exploit()
        
        # Проверяем результаты
        self.assertIn("successful_exploits", results)
        
        # В безопасном режиме эксплойты не запускаются реально
        self.automation.exploit_engine.run_exploit.assert_not_called()
    
    def test_report_generation(self):
        """Тестирование генерации отчета."""
        # Сначала выполняем сканирование и эксплуатацию
        self.automation.auto_scan("192.168.1.0/24")
        self.automation.auto_exploit()
        
        # Создаем временный файл для отчета
        with tempfile.NamedTemporaryFile(suffix='.json') as temp_file:
            # Генерируем отчет
            report_json = self.automation.report(temp_file.name)
            
            # Проверяем, что отчет не пустой
            self.assertTrue(len(report_json) > 0)
            
            # Проверяем, что отчет является валидным JSON
            report_data = json.loads(report_json)
            self.assertIn("scan_summary", report_data)
            self.assertIn("hosts", report_data)

class TestC1ExploitIntegration(unittest.TestCase):
    """Тесты для модуля интеграции с C1Brain."""
    
    def setUp(self):
        """Настройка перед каждым тестом."""
        # Патчим ExploitAutomation
        with patch('c1_exploit_integration.ExploitAutomation') as mock_exploit_automation:
            # Настраиваем заглушку для ExploitAutomation
            mock_instance = mock_exploit_automation.return_value
            mock_instance.auto_scan.return_value = {
                "live_hosts": ["192.168.1.1", "192.168.1.2"],
                "open_ports": {"192.168.1.1": [22, 80], "192.168.1.2": [443]},
                "detected_services": {"192.168.1.1": {22: "ssh", 80: "http"}, "192.168.1.2": {443: "https"}},
                "vulnerabilities": {"192.168.1.1": {80: [{"id": "CVE-2021-1234", "description": "Test vulnerability"}]}},
                "exploits_to_run": {"192.168.1.1": {80: [{"id": "EXP-1", "name": "Test Exploit"}]}}
            }
            mock_instance.auto_exploit.return_value = {
                "successful_exploits": {"192.168.1.1": {80: [{"id": "EXP-1", "name": "Test Exploit"}]}}
            }
            
            # Создаем экземпляр C1ExploitIntegration
            self.integration = C1ExploitIntegration(safe_mode=True)
    
    def test_scan_network(self):
        """Тестирование сканирования сети через интеграцию."""
        # Вызываем метод сканирования
        result = self.integration.scan_network("192.168.1.0/24", 5)
        
        # Проверяем, что метод вернул успешный результат
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["target_range"], "192.168.1.0/24")
        self.assertIn("summary", result)
        self.assertIn("top_vulnerable_hosts", result)
    
    def test_exploit_vulnerabilities(self):
        """Тестирование эксплуатации уязвимостей через интеграцию."""
        # Сначала выполняем сканирование
        self.integration.scan_network("192.168.1.0/24", 5)
        
        # Затем вызываем метод эксплуатации
        result = self.integration.exploit_vulnerabilities(["192.168.1.1"])
        
        # Проверяем, что метод вернул успешный результат
        self.assertEqual(result["status"], "success")
        self.assertIn("summary", result)
        self.assertIn("successful_hosts", result)
    
    def test_generate_report(self):
        """Тестирование генерации отчета через интеграцию."""
        # Сначала выполняем сканирование и эксплуатацию
        self.integration.scan_network("192.168.1.0/24", 5)
        self.integration.exploit_vulnerabilities(["192.168.1.1"])
        
        # Затем вызываем метод генерации отчета
        result = self.integration.generate_report(include_details=True)
        
        # Проверяем, что метод вернул успешный результат
        self.assertEqual(result["status"], "success")
        self.assertIn("report", result)
        self.assertIn("report_path", result)
    
    def test_c1_api_methods(self):
        """Тестирование API-методов для C1Brain."""
        # Тестируем обработчик scan_network
        result = self.integration.c1_scan_network({"target_range": "192.168.1.0/24", "concurrency": 5})
        self.assertEqual(result["status"], "success")
        
        # Тестируем обработчик exploit_vulnerabilities
        result = self.integration.c1_exploit_vulnerabilities({"target_hosts": ["192.168.1.1"]})
        self.assertEqual(result["status"], "success")
        
        # Тестируем обработчик generate_report
        result = self.integration.c1_generate_report({"include_details": True})
        self.assertEqual(result["status"], "success")
        
        # Тестируем обработчик set_safe_mode
        result = self.integration.c1_set_safe_mode({"safe_mode": False})
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["safe_mode"], False)
        
        # Тестируем обработчик get_vulnerability_details
        result = self.integration.c1_get_vulnerability_details({"vuln_id": "CVE-2021-1234"})
        self.assertEqual(result["status"], "success")
        self.assertIn("vulnerability", result)
        
        # Тестируем обработчик get_exploit_details
        result = self.integration.c1_get_exploit_details({"exploit_id": "EXP-1"})
        self.assertEqual(result["status"], "success")
        self.assertIn("exploit", result)

class TestIntegrationScenarios(unittest.TestCase):
    """Тесты для типичных сценариев использования системы."""
    
    def setUp(self):
        """Настройка перед каждым тестом."""
        # Патчим все зависимости
        self.patches = [
            patch('exploit_automation.ExploitEngine'),
            patch('exploit_automation.PortScanner'),
            patch('exploit_automation.HostScanner'),
            patch('exploit_automation.ServiceDetector'),
            patch('exploit_automation.VulnerabilityScanner')
        ]
        
        # Запускаем патчи
        self.mocks = [p.start() for p in self.patches]
        
        # Настраиваем заглушки
        self.mocks[2].return_value.scan_network.return_value = ["192.168.1.1", "192.168.1.2"]
        self.mocks[1].return_value.scan.return_value = [22, 80, 443]
        self.mocks[3].return_value.detect.return_value = "http"
        self.mocks[4].return_value.scan.return_value = [
            {"id": "CVE-2021-1234", "description": "Test vulnerability"}
        ]
        self.mocks[0].return_value.search_exploits.return_value = [
            {"id": "EXP-1", "name": "Test Exploit"}
        ]
    
    def tearDown(self):
        """Очистка после каждого теста."""
        # Останавливаем патчи
        for p in self.patches:
            p.stop()
    
    def test_full_automation_workflow(self):
        """Тестирование полного рабочего процесса автоматизации."""
        # Создаем экземпляр класса автоматизации
        automation = ExploitAutomation(safe_mode=True)
        
        # Сканируем сеть
        scan_results = automation.auto_scan("192.168.1.0/24")
        
        # Проверяем результаты сканирования
        self.assertIn("live_hosts", scan_results)
        self.assertIn("open_ports", scan_results)
        self.assertIn("detected_services", scan_results)
        self.assertIn("vulnerabilities", scan_results)
        self.assertIn("exploits_to_run", scan_results)
        
        # Эксплуатируем уязвимости
        exploit_results = automation.auto_exploit()
        
        # Проверяем результаты эксплуатации
        self.assertIn("successful_exploits", exploit_results)
        
        # Генерируем отчет
        with tempfile.NamedTemporaryFile(suffix='.json') as temp_file:
            report_json = automation.report(temp_file.name)
            
            # Проверяем, что отчет не пустой и является валидным JSON
            self.assertTrue(len(report_json) > 0)
            report_data = json.loads(report_json)
            self.assertIn("scan_summary", report_data)
    
    def test_c1brain_integration_workflow(self):
        """Тестирование рабочего процесса интеграции с C1Brain."""
        # Создаем заглушку для C1Brain
        c1_brain = MagicMock()
        
        # Создаем экземпляр класса интеграции
        integration = C1ExploitIntegration(safe_mode=True)
        
        # Регистрируем инструменты в C1Brain
        integration.register_c1_tools(c1_brain)
        
        # Проверяем, что метод register_tool был вызван 6 раз (по числу инструментов)
        self.assertEqual(c1_brain.register_tool.call_count, 6)
        
        # Имитируем вызов инструмента scan_network через C1Brain
        scan_params = {"target_range": "192.168.1.0/24", "concurrency": 5}
        result = integration.c1_scan_network(scan_params)
        
        # Проверяем результат
        self.assertEqual(result["status"], "success")
        
        # Имитируем вызов инструмента exploit_vulnerabilities через C1Brain
        exploit_params = {"target_hosts": ["192.168.1.1"]}
        result = integration.c1_exploit_vulnerabilities(exploit_params)
        
        # Проверяем результат
        self.assertEqual(result["status"], "success")
        
        # Имитируем вызов инструмента generate_report через C1Brain
        report_params = {"include_details": True}
        result = integration.c1_generate_report(report_params)
        
        # Проверяем результат
        self.assertEqual(result["status"], "success")

if __name__ == "__main__":
    unittest.main() 