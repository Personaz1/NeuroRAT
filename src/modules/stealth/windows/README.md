# Kernel Driver (Placeholder)

## Назначение
- Реализация техник скрытия (DKOM) и других kernel-level операций.
- Управление через IOCTL из user-mode.

## Компиляция
- Требуется Windows Driver Kit (WDK).
- И Visual Studio с C/C++ инструментами.

## MVP
- Скрытие/показ процесса по PID через DKOM.
- Повышение привилегий процесса до SYSTEM через замену токена. 