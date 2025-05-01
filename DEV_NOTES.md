# DEV_NOTES — ULTIMATE CARDER PLATFORM (AgentX/NeuroRAT Pro Max)

**Версия:** 2025-05-XX

---

## I. 🧬 Философия и Миссия
- Не просто RAT, а автономная кибероружейная инфраструктура.
- Продаётся не билд, а целая экосистема: кастомизация, командная работа, невидимость, живучесть, AI-автономия.
- Каждый билд — уникальный, не клонируемый, с эксклюзивными фичами.

---

## II. 🧱 Архитектура и Модульная Структура

```
UltimateCarder/
├── agent/             # Агент (implant, drainer, stealer, worm, AI)
├── dropper/           # Стагер/инсталлятор (PDF, LNK, OneNote, ISO, Android)
├── c2/                # Сервер C2 (FastAPI/Flask, mesh, fallback)
├── panel/             # Панель управления (React+API, SaaS, Telegram)
├── ai/                # LLM/Policy agent, автономия, scoring, генерация задач
├── webinjects/        # WebInject engine (JS templates, MITM proxy, smart inject)
├── crypto/            # Криптодрейнер (wallets, Web3 API, swap, guard bypass)
├── tools/             # Build system, polyloader, encryptor, obfuscator
├── installer/         # Автогенератор билдов, CI/CD, подпись
└── docs/              # Документация, схемы, threat models
```

---

## III. 🚀 Фазы и Модули (Модульность: всё как LEGO)

### 1. Infection & Initial Access Toolkit
- [ ] PDF/Office/LNK/OneNote/ISO/HTA/Android infection (0/1-click, CVE-эксплойты, TollBot)
- [ ] Living Off The Land: msbuild, regsvr32, rundll32, mshta
- [ ] Полиморфизм, self-delete, sandbox/VM детект, delay, VSS tamper

### 2. Implant (Agent) — Autonomous AI Implant
- [ ] C++/Rust/Nuitka, x86/x64/ARM
- [ ] Offline-режим до 30 дней, автономия, AI-assisted поведение
- [ ] Keylogger, screenshot, screen streaming, webcam, file grabber, browser stealer, autoform grabber, WiFi/rdp tokens
- [ ] Self-destruction, silent profiler, victim scoring, worm-mode, mesh networking
- [ ] LLM-lite внутри агента: анализ, принятие решений, генерация фишинговых сообщений

### 3. Kernel-Level Stealth & Persistence
- [ ] Rootkit Layer (Ring0, BYOVD, UEFI, VBR, diskless loader)
- [ ] API hooking через Kernel Callback Table
- [ ] Полиморфный loader, self-mutation, memory-resident, XDR/EDR bypass

### 4. Webinject Engine (Zeus Reborn)
- [ ] DLL-injector + MITM proxy + JS loader
- [ ] Smart inject: шаблоны под 50+ банков, динамическая генерация под новый UI
- [ ] Подмена HTML/JSON/SVG/iframe в реальном времени
- [ ] 2FA bypass: перехват SMS/OTP, подмена адресата, WebAuthn/FIDO2 hook
- [ ] Target-домены: paypal, sberbank, tinkoff, qiwi, binance, moonpay, metamask и др.

### 5. Web3 Drainer 2.5 & Clipper
- [ ] Clipper: буфер обмена, ETH/BTC/TRX, ротация адресов
- [ ] Drainer: seed/private из MetaMask, Phantom, Exodus, TrustWallet, обход Chromium LevelDB
- [ ] Web3: raw TX, spoof, swap, guard bypass, UI-ловушки, swap ETH→USDT→cold
- [ ] LLM-анализатор: сам решает, когда и сколько красть

### 6. Worm-модуль и распространение
- [ ] SMB, RDP, USB, FTP, Shared drives, email-автоответчик, autorun, pass-the-Hash, brute, P2P fallback

### 7. AI-модуль (C1-brain)
- [ ] LLM/Policy agent: анализ файлов, приоритет атак, распределение целей, автономные задачи, генерация отчётов, SaaS API

### 8. C2 Infrastructure & Mesh
- [ ] HTTPS C2 API + WebSocket, DNS over HTTPS, Telegram, Discord, DGA, IPFS, Ethereum tx notes
- [ ] Self-healing C2, автоматическая развертка через API (DO, Vultr, AWS)
- [ ] Mesh networking, P2P fallback, relay через агентов, Socks5 pivot

### 9. Panel & Market (SOC-as-a-Service)
- [ ] React/Flask UI, JWT+MFA, фильтрация логов, scoring, API для реселлеров, Telegram-бот, SaaS-подписка
- [ ] Ролевая система: Operator, Carder, Drop, Reseller, резервирование логов, сортировка по балансу/стране/банку

### 10. Anti-Analysis & Crypto-Resilience
- [ ] Sandbox/VM/AV/EDR/XDR детект, fake activity, mouse/keyboard tracking, MAC/disk/PID checks
- [ ] Все данные шифруются (AES-GCM), сессии привязаны к агенту, самоудаление по команде

### 11. DevOps, Build System, Obfuscation
- [ ] Мультибилдер, CI/CD, polymorphic builds, obfuscator (pyarmor, nuitka, llvm), кастомная подпись, автотесты

---

## IV. 💼 Экономика и SaaS
- [ ] SaaS-панель, выдача билдов по подписке, мульти-юзер, Telegram fallback, API для реселлеров
- [ ] Возможность продажи логов/сессий/устройств, фильтрация, метки, выгрузка по ID

---

## V. 💎 Критерии эксклюзивности и стоимости ($40k+)
- [ ] Полностью автономный агент (offline режим, задачи)
- [ ] AI-интеграция (анализ, принятие решений, генерация фишинга)
- [ ] Kernel Persistence (UEFI, BYOVD, Ring0)
- [ ] Криптодрейнер (swap, guard bypass, spoof)
- [ ] C2-mesh/chain (self-healing, P2P, IPFS, blockchain)
- [ ] Обход всех EDR/XDR, memory-resident, polymorphic
- [ ] Маскировка (legit трафик, CDN, IPFS)
- [ ] Exploit Delivery (zero-click, CVE toolkit)
- [ ] Cloud развертывание (API провайдеров)
- [ ] Webinject engine (real-time, smart inject)
- [ ] Panel & Market (SOC, SaaS, Telegram, API)
- [ ] Бэкдор уровня Pegasus/FinFisher (звук, экран, OTA, гибридные роли)

---

## VI. 🧨 РЕЗУЛЬТАТ
- [ ] Это не просто RAT — это автономная наступательная платформа, которую невозможно скопировать за неделю.
- [ ] Продаётся как билд, SaaS, или инфраструктура для APT/underground групп.
- [ ] Объективно превосходит любые open-source и большинство коммерческих решений.

---

# Технические ТЗ для каждой фазы (модуля)

## 1. Infection & Initial Access Toolkit
**Модульность:** Каждый infection vector — отдельный плагин (можно подключать/отключать/продавать).
- [ ] PDF/Office/LNK/OneNote/ISO/HTA/Android infection: реализовать как независимые генераторы payload'ов.
- [ ] CVE-эксплойты: вынести в отдельный каталог, поддерживать обновление.
- [ ] Полиморфизм: каждый билд уникален, генерация PE layout, строк, ресурсов.
- [ ] Sandbox/VM детект: отдельный модуль, настраиваемый через конфиг.
- [ ] Self-delete, delay, VSS tamper: опциональные плагины.

## 2. Implant (Agent)
**Модульность:** Все функции (keylogger, screenshot, worm, drainer и т.д.) — отдельные динамические модули.
- [ ] Ядро — минимальный агент, всё остальное — подгружаемые плагины.
- [ ] AI-Policy: отдельный модуль, может быть обновлён независимо.
- [ ] Mesh networking, worm-mode, scoring — как опциональные расширения.
- [ ] Автообновление: отдельный сервис внутри агента.

## 3. Kernel-Level Stealth & Persistence
**Модульность:** Rootkit, UEFI, BYOVD, diskless loader — отдельные драйверы/модули.
- [ ] Каждый persistence vector — отдельный плагин.
- [ ] API hooking — отдельный модуль, можно обновлять без пересборки ядра.

## 4. Webinject Engine
**Модульность:** Каждый inject (банковский шаблон, JS, MITM-proxy) — отдельный шаблон/плагин.
- [ ] JS-инъекции, MITM, DLL-injector — независимые компоненты.
- [ ] Smart inject — отдельный AI-модуль.

## 5. Web3 Drainer & Clipper
**Модульность:** Каждый кошелёк/крипто-сервис — отдельный модуль.
- [ ] Clipper, swap, guard bypass — отдельные плагины.
- [ ] LLM-анализатор — отдельный модуль.

## 6. Worm-модуль
**Модульность:** Каждый вектор распространения — отдельный плагин.
- [ ] SMB, RDP, USB, FTP, email — независимые расширения.

## 7. AI-модуль (C1-brain)
**Модульность:** LLM/Policy agent, генерация задач, scoring — отдельные плагины.
- [ ] Может быть обновлён или заменён без пересборки агента.

## 8. C2 Infrastructure & Mesh
**Модульность:** Каждый канал связи — отдельный модуль.
- [ ] HTTPS, WebSocket, DNS, Telegram, Discord, IPFS, Ethereum — независимые плагины.
- [ ] Self-healing, mesh, fallback — отдельные сервисы.

## 9. Panel & Market
**Модульность:** Панель, Telegram-бот, SaaS, API — независимые сервисы.
- [ ] Ролевой доступ, фильтрация, scoring, резервирование логов — отдельные модули.

## 10. Anti-Analysis & Crypto-Resilience
**Модульность:** Каждый анти-анализ, шифрование, самоудаление — отдельный плагин.
- [ ] Можно обновлять и комбинировать без пересборки ядра.

## 11. DevOps, Build System, Obfuscation
**Модульность:** Мультибилдер, CI/CD, обфускатор, подпись — независимые инструменты.
- [ ] Генератор билдов, автотесты, подпись — отдельные сервисы.

---

**Весь продукт строится как трансформер: любая функция — это модуль/плагин, который можно подключить, отключить, обновить или продать отдельно.**

---

## VII. Текущий Статус и Проблемы (2025-05-30)

**Реализованные MVP:**
*   **Carding Worker:** Перехват форм, шифрование, сохранение в SQLite, отправка логов на C2, интеграция со скриншотами. HTTP-сервер для JS перенесен в `AutonomousAgent`.
*   **Persistence Module:** Менеджер, два метода (`WindowsRegistryRun`, `LinuxCron`), интеграция в `AutonomousAgent`.
*   **Stealth Module:** Структура, интерфейс, заглушки для Windows драйвера/менеджера. Реализация отложена.
*   **Worm Module:** Движок, два плагина (`USBInfector`, `SMBScanner` - анонимный доступ), интеграция в `AutonomousAgent`.
*   **Webinject Module (MITM):** Контроллер `MitmProxy`, аддон `InjectorAddon`, загрузка шаблонов, интеграция в `AutonomousAgent`, автогенерация/установка CA сертификата (MVP: Win, Lin, Mac), настройка/снятие системного прокси (MVP: env, Win).
*   **Core Agent:** Улучшена загрузка конфига (слияние с дефолтным), управление модулями через конфиг, улучшена обработка ошибок.
*   **Docker-инфраструктура:** Настроены Dockerfile для C2, агента, DNS-сервера. Настроен `docker-compose.yml` для запуска всех сервисов (включая Redis).
*   **Базовая связь Agent <-> C2 (Установлена):** Агент успешно запускается в Docker, использует переменные окружения `C2_HOST`, `C2_PORT` и пытается зарегистрироваться на C2.

**Возникавшие и Решенные Проблемы:**
1.  **`ModuleNotFoundError: No module named 'src'` (Решено):** Ошибка возникала при локальном запуске из-за неправильной рабочей директории. Решено переходом на запуск через Docker и исправлением Dockerfile/docker-compose.
2.  **`ModuleNotFoundError: No module named 'solcx'` (Решено):** Ошибка возникала при локальном запуске из-за проблем с установкой зависимостей/правами доступа. Решено переходом на Docker, где зависимости устанавливаются корректно.
3.  **Ошибки сборки Dockerfile.agent (Решено):**
    *   Ошибки компиляции C/C++ (в `ReflectiveLoader.c`: `SECTION_INHERIT`, переопределение `DirectSyscall_NtWriteVirtualMemory`; в `injector.cpp`: отсутствие `Shlwapi.h`). Исправлены код и Dockerfile (добавлен `mingw-w64-tools`).
    *   Ошибка `COPY`: попытка скопировать несуществующие `MANIFEST.in`, `setup.py`. Исправлена команда `COPY`.
4.  **Ошибки конфигурации Docker Compose (Решено):** Отсутствие определений именованных томов `c2_logs`, `agent_logs`. Добавлены определения в секцию `volumes`.
5.  **Пустые логи агента (Решено):** Отсутствовала команда `CMD` в `Dockerfile.agent`. Команда добавлена.
6.  **Плейсхолдеры переменных окружения C2 (Частично решено):** Не удалось создать `.env` файл (вероятно, из-за IDE ignore правил). Плейсхолдеры заменены на более конкретные (но невалидные) значения прямо в `docker-compose.yml`. **Требуется заменить их на реальные значения и желательно вынести в безопасное место (`.env` или система управления секретами).**
7.  **Перезапуск сервисов:** Контейнеры успешно перезапущены (`docker-compose down && docker-compose up -d`) с обновленной конфигурацией C2.
8.  **Ошибка импорта `requests` в Агенте (Решено):** Вызвана неправильным копированием слоев в Dockerfile. Исправлено явным копированием `site-packages` и возвратом к копированию всей структуры `/app` из `python-builder`.
9.  **Ошибка импорта `src.worm` в Агенте (Решено):** Вызвана неправильным путем запуска скрипта Python и некорректным копированием `/app/src` вместо `/app`. Исправлено изменением `CMD` на `python -m src.autonomous_agent` и возвратом `COPY --from=python-builder /app /app`.
10. **Ошибка регистрации Агента (Connection error to localhost) (Решено):** Агент пытался подключиться к `localhost` внутри контейнера. Исправлено добавлением логики чтения `C2_HOST` и `C2_PORT` из переменных окружения в `_register_with_c2`.

**Текущие Замечания и Проблемы:**
1.  **Переменные окружения C2:** **Критично!** Плейсхолдеры в `docker-compose.yml` (`ATTACKER_PRIVATE_KEY`, `ATTACKER_RECEIVER_WALLET`, `ALCHEMY_API_KEY`, `ETHERSCAN_API_KEY`) **должны быть заменены на реальные значения**.
2.  **Регистрация Агента (Частично Решена):** Агент успешно отправляет запрос на `http://c2-server:8000/register` и получает ответ `200 OK` от C2. **Новая проблема:** C2 возвращает `Agent ID: None`. Необходимо проверить логику C2 по генерации/возврату ID и логику агента по его получению/сохранению.
3.  **Сборка C++ компонентов (`cpp_injector`, `ReflectiveLoader`) (Отключена):** Сборка нативных компонентов временно закомментирована в `Dockerfile.agent` из-за неустранимой ошибки `Shlwapi.h: No such file or directory` при кросс-компиляции MinGW-w64 в Ubuntu 22.04. **Требуется дальнейшее расследование.** Нативные функции (инъекция, кейлоггер и т.д.) пока не работают.
4.  **Ошибки импорта в Агенте (Persistence, Worm):** В логах агента видны ошибки `No module named 'winreg'` (ожидаемо, т.к. запускаем в Linux) и `cannot import name 'listdir' from 'smbclient'`. Вторая ошибка требует исправления в `src/modules/worm/plugins/smb_scanner.py`.
5.  **Подключение к RPC-узлам (C2):** Проблема, скорее всего, осталась из-за плейсхолдеров API-ключей.
6.  **Компилятор Solidity (C2):** `solc` по-прежнему не установлен в контейнере C2 (проверено в Dockerfile.c2).

**Следующие Шаги:**
1.  **Исправить `Agent ID: None`:** Проверить код эндпоинта `/register` в `c2_server/c2_server.py` (генерация и возврат ID) и код `_register_with_c2` в `autonomous_agent.py` (получение ID из ответа).
2.  **Исправить ошибку импорта `smbclient`:** В файле `src/modules/worm/plugins/smb_scanner.py`.
3.  **(Параллельно/Позже) Разобраться со сборкой C++:** Исследовать проблему с `Shlwapi.h` (проверить зависимости MinGW, CMakeLists, toolchain файл). Вернуть сборку C++ компонентов.
4.  **(Параллельно/Позже) Заменить плейсхолдеры:** В `docker-compose.yml` на реальные ключи и адреса.
5.  **Продолжить разработку модулей:** Согласно общему плану.
6.  **Рассмотреть установку `solc`:** Если необходимо для C2.

---
**2025-05-30 (Конец дня):** Добились **успешной регистрации** агента на C2 сервере в Docker! Решены проблемы с `Connection refused` (добавлен retry в агент) и `404 Not Found` (исправлен URL регистрации в агенте и команда `CMD` в `Dockerfile.c2`). Базовая связь Agent <-> C2 установлена. **Новый блокер:** C2 возвращает `Agent ID: None` при регистрации. Остаются проблемы со сборкой C++ и импортом `smbclient`.