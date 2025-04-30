# db/

**carding.db** — локальная шифрованная база данных для хранения перехваченных форм оплаты (карты, CVV, exp, OTP и др.).

- Используется SQLite с шифрованием (Fernet/AES).
- Таблица: cards (id, domain, data, screenshot, timestamp, sent)
- Все данные шифруются перед записью. 