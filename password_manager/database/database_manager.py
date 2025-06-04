from sqlcipher3 import dbapi2 as sqlcipher
import time
import os
from typing import Optional, List, Dict, Any
from password_manager.utils.logging_config import setup_logging
from password_manager.utils.secure_data_utils import ensure_directories_exist
from password_manager.security.password_security import PasswordSecurity
from password_manager.encryption import EncryptionService

logger = setup_logging()

# Константы для повторного подключения
MAX_RETRIES = 3  # Максимальное количество попыток повторного подключения
RETRY_DELAY = 1  # Задержка между попытками повторного подключения (в секундах)
DB_TIMEOUT = 30  # Таймаут подключения к базе данных (в секундах)


class DatabaseManager:
    def __init__(self, config=None):
        """ Инициализация менеджера базы данных
        Args: config: Опциональный экземпляр Config. Если не предоставлен, будет создан новый.
        """
        if config is None:
            # Импортируем здесь, чтобы избежать циклической зависимости
            from password_manager.config import Config
            config = Config()
        self.config = config
        self.db_path = self.config.database_path
        self.conn = None
        self.cur = None
        self.retry_count = 0
        self.encryption_service = EncryptionService(base_dir=os.path.dirname(self.db_path))

    def __enter__(self):
        # Убеждаемся, что master_password (фраза) установлен в Config
        if not self.config.master_password:
            # Это условие не должно срабатывать, если __main__.py правильно вызывает ensure_master_password_initialized
            logger.error("Master password (passphrase) is not set in Config when entering DatabaseManager context.")
            raise ValueError("Database password (passphrase) is not set. Please ensure it is provided first.")
            
        while self.retry_count < MAX_RETRIES:
            try:
                self.conn = sqlcipher.connect(self.db_path, timeout=DB_TIMEOUT)
                self.conn.row_factory = sqlcipher.Row
                self.cur = self.conn.cursor()
                # Получаем фразу из конфига
                passphrase = self.config.master_password
                # Экранируем одинарные кавычки в фразе, если они есть
                escaped_passphrase = passphrase.replace("'", "''")
                # Устанавливаем ключ (фразу) и параметры SQLCipher 4
                self.cur.execute(f"PRAGMA key = '{escaped_passphrase}'")
                self.cur.execute("PRAGMA cipher_compatibility = 4")
                # Проверка, что база данных читаема с этим ключом и настройками
                try:
                    self.cur.execute("SELECT count(*) FROM sqlite_master")
                    self.cur.fetchone()
                    logger.info("Database key/passphrase verified successfully, connection is readable.")
                except sqlcipher.DatabaseError as e:
                    logger.error(f"Failed to read database with provided passphrase. SQLCipher Error: {type(e).__name__} - {str(e)}")
                    logger.debug(f"Passphrase used during failed read attempt: '{escaped_passphrase[:5]}...'")
                    raise ValueError("Invalid database passphrase or database corrupted.")
                return self.cur
            except sqlcipher.OperationalError as e:
                if "database is locked" in str(e):
                    self.retry_count += 1
                    if self.retry_count >= MAX_RETRIES:
                        logger.error("Maximum retry attempts reached, database is still locked")
                        raise
                    logger.warning(f"Database is locked, retrying in {RETRY_DELAY} seconds... (Attempt {self.retry_count}/{MAX_RETRIES})")
                    time.sleep(RETRY_DELAY)
                    continue
                logger.error(f"Database error: {e}")
                raise
            except Exception as e:
                logger.error(f"Unexpected error in DatabaseManager.__enter__: {e}")
                raise
        raise sqlcipher.OperationalError("Failed to connect to database after maximum retry attempts")

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
                logger.error(f"Операция с базой данных не удалась: {exc_val}")
        except Exception as e:
            logger.error(f"Ошибка при завершении работы с базой данных: {e}")
        finally:
            if self.cur:
                self.cur.close()
            if self.conn:
                self.conn.close()

    def initialize_database(self):
        """Инициализация таблиц и индексов базы данных"""
        try:
            with self as cur:
                # Создаём таблицу пользователей
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS Users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        login TEXT NOT NULL UNIQUE,
                        pwd TEXT NOT NULL
                    )
                ''')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_users_login ON Users(login)')
                logger.info("Таблица Users и индексы созданы/проверены")

                # Создаём таблицу паролей
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS Passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        username TEXT NOT NULL,
                        site TEXT NOT NULL,
                        password TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
                    )
                ''')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON Passwords(user_id)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_passwords_site ON Passwords(site)')
                logger.info("Таблица Passwords и индексы созданы/проверены")

                # Проверяем таблицы
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                tables = cur.fetchall()
                logger.info(f"Существующие таблицы в базе данных: {[table[0] for table in tables]}")
        except Exception as e:
            logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
            raise

    def verify_user(self, username: str, password: str) -> Optional[int]:
        """Проверка учётных данных пользователя и возврат user_id, если они действительны"""
        try:
            with self as cur:
                cur.execute("SELECT id, pwd FROM Users WHERE login = ?", (username,))
                user_data = cur.fetchone()
                
                if not user_data:
                    logger.warning(f"Пользователь {username} не найден")
                    return None
                    
                user_id, stored_password = user_data
                
                # Обрабатываем хеши паролей как в строковом, так и в байтовом представлении
                if isinstance(stored_password, bytes):
                    stored_password = stored_password.decode('utf-8')
                
                # Проверяем пароль с использованием PasswordSecurity
                password_security = PasswordSecurity()
                if password_security.verify_password(stored_password, password):
                    logger.info(f"Пользователь {username} успешно аутентифицирован")
                    return user_id
                else:
                    logger.warning(f"Проверка пароля не удалась для пользователя {username}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка при проверке пользователя {username}: {str(e)}")
            return None

    def register_user(self, username: str, password: str) -> bool:
        """Регистрация нового пользователя с хешированием пароля"""
        try:
            # Хешируем пароль перед сохранением
            password_security = PasswordSecurity()
            hashed_password = password_security.hash_password(password)
            
            with self as cur:
                cur.execute("INSERT INTO Users (login, pwd) VALUES (?, ?) RETURNING id", (username, hashed_password))
                user_id = cur.fetchone()[0]
                
                # Создаём директории пользователя, если это необходимо (проверить реализацию ensure_directories_exist)
                # ensure_directories_exist(user_id) # Возможно, эта логика должна быть в EncryptionService или вызываться с правильным путем
                
                # Инициализация ключей шифрования для нового пользователя
                # Используем self.encryption_service, который уже инициализирован с правильным base_dir
                fernet_created, aes_created = self.encryption_service.force_create_keys(user_id)
                
                if not fernet_created or not aes_created:
                    logger.warning(f"Не удалось создать ключи шифрования для user_id={user_id}: fernet={fernet_created}, aes={aes_created}")
                else:
                    logger.info(f"Успешно созданы ключи шифрования для user_id={user_id}")
                
                logger.info(f"Пользователь успешно зарегистрирован: {username}")
                return True
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                logger.warning(f"Не удалось зарегистрировать пользователя {username}: Имя пользователя уже существует")
            else:
                logger.error(f"Ошибка при регистрации пользователя {username}: {str(e)}")
            return False

    def get_user_passwords(self, user_id: int) -> List[Dict[str, Any]]:
        """Получение всех паролей пользователя"""
        with self as cur:
            cur.execute("""
                SELECT id, username, site, password 
                FROM Passwords 
                WHERE user_id = ?
                ORDER BY id DESC
            """, (user_id,))
            return cur.fetchall()

    def search_passwords_by_site(self, user_id: int, site_term: str) -> List[Dict[str, Any]]:
        """Поиск паролей по названию сайта с использованием индекса сайтов"""
        with self as cur:
            # Используем LIKE с нечувствительным к регистру шаблоном поиска для сопоставления префикса
            cur.execute("""
                SELECT id, username, site, password 
                FROM Passwords 
                WHERE user_id = ? AND site LIKE ? COLLATE NOCASE
                ORDER BY id DESC
            """, (user_id, f"{site_term}%"))
            return cur.fetchall()

    def add_password(self, user_id: int, username: str, site: str, password: str) -> int:
        """Добавление новой записи пароля"""
        with self as cur:
            encrypted_password = self.encryption_service.encrypt_password(password, user_id)
            cur.execute("""
                INSERT INTO Passwords (user_id, username, site, password)
                VALUES (?, ?, ?, ?)
                RETURNING id
            """, (user_id, username, site, encrypted_password))
            return cur.fetchone()[0]

    def update_password(self, password_id: int, username: str, site: str, password: str, user_id: int) -> bool:
        """Обновление существующей записи пароля"""
        with self as cur:
            encrypted_password = self.encryption_service.encrypt_password(password, user_id)
            cur.execute("""
                UPDATE Passwords 
                SET username = ?, site = ?, password = ?
                WHERE id = ?
            """, (username, site, encrypted_password, password_id))
            return True

    def delete_password(self, password_id: int) -> bool:
        """Удаление записи пароля"""
        with self as cur:
            cur.execute("DELETE FROM Passwords WHERE id = ?", (password_id,))
            return True

    def get_username_by_id(self, user_id: int) -> str:
        """Получение имени пользователя по ID пользователя"""
        with self as cur:
            cur.execute("SELECT login FROM Users WHERE id = ?", (user_id,))
            result = cur.fetchone()
            return result[0] if result else "user"

    def get_user_ids(self) -> List[int]:
        """Получение всех ID пользователей из базы данных"""
        try:
            with self as cur:
                cur.execute("SELECT id FROM Users")
                return [row[0] for row in cur.fetchall()]
        except Exception as e:
            logger.error(f"Не удалось получить ID пользователей: {str(e)}")
            return []

    def get_last_password(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Получение последнего добавленного пароля для пользователя"""
        try:
            with self as cur:
                cur.execute("""
                    SELECT id, username, site, password 
                    FROM Passwords 
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                """, (user_id,))
                return cur.fetchone()
        except Exception as e:
            logger.error(f"Не удалось получить последний пароль для пользователя {user_id}: {str(e)}")
            return None
