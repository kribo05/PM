import json
import logging
import csv
import io
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from cryptography.fernet import Fernet
from ..database.database_manager import DatabaseManager
from ..encryption.key_manager import FernetKeyManager

logger = logging.getLogger(__name__)


class DataTransferManager:
    def __init__(self, user_id: int, key_manager: FernetKeyManager):
        self.user_id = user_id
        self.key_manager = key_manager
    
    def export_data(self) -> Dict[str, Any]:
        try:
            data = {
                "metadata": {
                    "version": "1.0",
                    "timestamp": datetime.now().isoformat(),
                    "user_id": self.user_id
                },
                "data": {
                    "passwords": [],
                    "user_info": None
                }
            }
            
            with (DatabaseManager() as cur):
                # Экспорт информации о пользователе
                cur.execute("""
                    SELECT id, login, pwd 
                    FROM Users 
                    WHERE id = ?
                """, (self.user_id,))
                user_data = cur.fetchone()
                if user_data is not None:
                    data["data"]["user_info"] = {
                        "id": user_data[0],
                        "login": user_data[1]
                    }
                else:
                    logger.warning(f"Данные пользователя не найдены для user_id: {self.user_id}")
                    data["data"]["user_info"] = None
                
                # Экспорт паролей
                cur.execute("""
                    SELECT id, username, site, password 
                    FROM Passwords 
                    WHERE user_id = ?
                """, (self.user_id,))
                passwords = cur.fetchall()
                data["data"]["passwords"] = [
                    {
                        "id": p[0],
                        "username": p[1],
                        "site": p[2],
                        "password": p[3]
                    }
                    for p in passwords
                ]
            
            return data
        except Exception as e:
            logger.error(f"Не удалось экспортировать данные: {str(e)}")
            raise

    def export_data_to_csv(self) -> str:
        """Экспорт паролей в формат CSV для совместимости
        
        Returns:
            Строка, содержащая CSV-данные
        """
        try:
            # Используем StringIO для создания CSV в памяти
            output = io.StringIO()
            csv_writer = csv.writer(output)
            
            # Записываем заголовок
            csv_writer.writerow(['Site', 'Username', 'Password'])
            
            db_manager = DatabaseManager()
            with db_manager as cur:
                # Получаем все пароли пользователя
                cur.execute("""
                    SELECT id, username, site, password 
                    FROM Passwords 
                    WHERE user_id = ?
                    ORDER BY site
                """, (self.user_id,))
                
                passwords = cur.fetchall()
                
                # Создаем сервис шифрования для расшифровки паролей
                from ..encryption import EncryptionService
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                encryption_service = EncryptionService(base_dir=base_dir)
                
                # Добавляем каждый пароль в CSV
                for pwd in passwords:
                    username = pwd['username']
                    site = pwd['site']
                    encrypted_password = pwd['password']
                    
                    # Расшифровываем пароль
                    try:
                        decrypted_password = encryption_service.decrypt_password(encrypted_password, self.user_id)
                        csv_writer.writerow([site, username, decrypted_password])
                    except Exception as e:
                        logger.error(f"Не удалось расшифровать пароль для сайта {site}: {str(e)}")
                        csv_writer.writerow([site, username, "DECRYPTION_FAILED"])
            
            # Получаем содержимое CSV как строку
            csv_content = output.getvalue()
            output.close()
            return csv_content
            
        except Exception as e:
            logger.error(f"Не удалось экспортировать данные в CSV: {str(e)}")
            raise

    def encrypt_export(self, data: Dict[str, Any]) -> bytes:
        try:
            # Получение текущего ключа и создание экземпляра Fernet
            key = self.key_manager.get_current_key()
            fernet = Fernet(key)
            # Преобразование данных в JSON и шифрование
            json_data = json.dumps(data)
            return fernet.encrypt(json_data.encode())
        except Exception as e:
            logger.error(f"Не удалось зашифровать экспортируемые данные: {str(e)}")
            raise

    def decrypt_import(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Расшифровка импортируемых данных"""
        try:
            # Сначала пробуем с текущим ключом
            key = self.key_manager.get_current_key()
            fernet = Fernet(key)
            
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                return json.loads(decrypted_data.decode())
            except Exception:
                # Если текущий ключ не подходит, пробуем с предыдущими ключами
                previous_keys = self.key_manager.get_previous_keys()
                for prev_key in previous_keys:
                    try:
                        fernet = Fernet(prev_key)
                        decrypted_data = fernet.decrypt(encrypted_data)
                        return json.loads(decrypted_data.decode())
                    except Exception:
                        continue
                
                # Если все ключи не подошли
                raise ValueError("Не удалось расшифровать данные ни одним из доступных ключей")
                
        except Exception as e:
            logger.error(f"Не удалось расшифровать импортируемые данные: {str(e)}")
            raise

    def import_data(self, data: Dict[str, Any]) -> bool:
        try:
            # Проверка структуры данных
            if not isinstance(data, dict) or "metadata" not in data or "data" not in data:
                raise ValueError("Неверный формат резервной копии")

            # Проверка совместимости версии
            version = data["metadata"].get("version", "1.0")
            if version != "1.0":
                raise ValueError(f"Неподдерживаемая версия резервной копии: {version}")

            # Проверка ID пользователя
            if data["metadata"]["user_id"] != self.user_id:
                raise ValueError("Несоответствие ID пользователя")
            
            # Проверка структуры данных
            if not isinstance(data["data"], dict) or "passwords" not in data["data"]:
                raise ValueError("Неверная структура данных")
            
            with DatabaseManager() as cur:
                # Начинаем транзакцию
                cur.execute("BEGIN")
                try:
                    # Импортируем информацию о пользователе, если нужно
                    user_info = data["data"].get("user_info")
                    if user_info and isinstance(user_info, dict):
                        cur.execute("""
                            UPDATE Users 
                            SET login = ? 
                            WHERE id = ?
                        """, (user_info["login"], self.user_id))
                    
                    # Сначала удаляем существующие пароли
                    cur.execute("DELETE FROM Passwords WHERE user_id = ?", (self.user_id,))
                    
                    # Импортируем пароли
                    for p in data["data"]["passwords"]:
                        if not all(k in p for k in ["username", "site", "password"]):
                            raise ValueError("Неверный формат записи пароля")
                        cur.execute("""
                            INSERT INTO Passwords (user_id, username, site, password)
                            VALUES (?, ?, ?, ?)
                        """, (self.user_id, p["username"], p["site"], p["password"]))
                    
                    # Завершаем транзакцию
                    cur.execute("COMMIT")
                except Exception:
                    # Откатываем при ошибке
                    cur.execute("ROLLBACK")
                    raise
            
            return True
        except Exception as e:
            logger.error(f"Не удалось импортировать данные: {str(e)}")
            raise

    def import_data_from_csv(self, csv_file_path: str) -> int:
        """Импорт паролей из CSV-файла
        Args: csv_file_path: Путь к CSV-файлу для импорта
        Returns: Количество успешно импортированных паролей
        Raises:
            ValueError: Если формат CSV-файла некорректен
            FileNotFoundError: Если CSV-файл не найден
            IOError: Если возникла ошибка при чтении CSV-файла
        """
        try:
            if not os.path.exists(csv_file_path):
                raise FileNotFoundError(f"CSV-файл не найден: {csv_file_path}")
                
            # Получаем сервис шифрования для шифрования паролей
            from ..encryption import EncryptionService
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            encryption_service = EncryptionService(base_dir=base_dir)
            
            passwords_imported = 0
            valid_passwords = []
            
            # Читаем CSV-файл
            with open(csv_file_path, 'r', newline='', encoding='utf-8') as csv_file:
                csv_reader = csv.reader(csv_file)
                
                # Получаем заголовок
                header = next(csv_reader)
                
                # Анализ заголовков для определения формата
                normalized_header = [h.strip().lower() for h in header]
                
                # Автоматический поиск колонок по названиям
                site_idx = -1
                username_idx = -1
                password_idx = -1
                
                # Поиск колонки сайта/URL
                for idx, column in enumerate(normalized_header):
                    if column in ['site', 'url', 'web site', 'website', 'login uri', 'name', 'title']:
                        site_idx = idx
                        break
                
                # Поиск колонки имени пользователя
                for idx, column in enumerate(normalized_header):
                    if column in ['username', 'login', 'user', 'login name', 'login_username', 'email']:
                        username_idx = idx
                        break
                        
                # Поиск колонки пароля
                for idx, column in enumerate(normalized_header):
                    if column in ['password', 'pass', 'secret', 'login_password']:
                        password_idx = idx
                        break
                
                # Если определение колонок не удалось, пытаемся использовать стандартный формат
                if site_idx == -1 or username_idx == -1 or password_idx == -1:
                    if len(header) >= 3:
                        site_idx = 0
                        username_idx = 1
                        password_idx = 2
                    else:
                        raise ValueError("Формат CSV не распознан")
                
                # Обработка строк CSV
                for row in csv_reader:
                    if len(row) <= max(site_idx, username_idx, password_idx):
                        logger.warning(f"Пропуск строки с недостаточным количеством столбцов: {row}")
                        continue
                        
                    site = row[site_idx].strip()
                    username = row[username_idx].strip()
                    password = row[password_idx].strip()
                    
                    # Пропуск пустых записей
                    if not site or not username or not password:
                        continue
                        
                    # Шифрование пароля
                    encrypted_password = encryption_service.encrypt_password(password, self.user_id)
                    valid_passwords.append({
                        'site': site,
                        'username': username,
                        'password': encrypted_password
                    })
            
            # Сохранение в базу данных
            with DatabaseManager() as cur:
                cur.execute("BEGIN")
                try:
                    for entry in valid_passwords:
                        cur.execute("""
                            INSERT INTO Passwords (user_id, username, site, password)
                            VALUES (?, ?, ?, ?)
                        """, (self.user_id, entry['username'], entry['site'], entry['password']))
                        passwords_imported += 1
                    
                    cur.execute("COMMIT")
                except Exception as e:
                    cur.execute("ROLLBACK")
                    raise
            
            return passwords_imported
                
        except Exception as e:
            logger.error(f"Не удалось импортировать данные из CSV: {str(e)}")
            raise
