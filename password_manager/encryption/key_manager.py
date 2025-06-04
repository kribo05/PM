import base64
import json
import os
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet, InvalidToken
from password_manager.utils.secure_data_utils import get_user_keys_dir
from password_manager.security.exceptions import (
    KeyManagementError,
    KeyCreationError,
    KeyValidationError,
    KeyBackupError,
    KeyRotationError
)
from password_manager.security.key_recovery import KeyRecoveryManager
from password_manager.security.windows_permissions import set_windows_secure_permissions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from password_manager.utils.logging_config import setup_logging

# Initialize logger using singleton pattern
logger = setup_logging()


class KeyData:
    """Класс для хранения данных о ключе шифрования"""
    def __init__(self, key: str, created_at: str, expires_at: str):
        """ Инициализация данных ключа
        Args: key: Ключ в формате base64
            created_at: Дата создания в формате ISO
            expires_at: Дата истечения в формате ISO
        """
        self._key = None
        self._created_at = None
        self._expires_at = None
        self.key = key
        self.created_at = created_at
        self.expires_at = expires_at
    
    @property
    def key(self) -> str:
        return self._key
    
    @key.setter
    def key(self, value: str):
        try:
            # Проверяем, что ключ в формате base64
            base64.b64decode(value)
            self._key = value
        except Exception as e:
            raise KeyValidationError("Неверный формат ключа (должен быть в base64)", e)
    
    @property
    def created_at(self) -> str:
        return self._created_at
    
    @created_at.setter
    def created_at(self, value: str):
        try:
            # Проверяем формат даты
            datetime.fromisoformat(value)
            self._created_at = value
        except Exception as e:
            raise KeyValidationError("Неверный формат даты создания", e)
    
    @property
    def expires_at(self) -> str:
        return self._expires_at
    
    @expires_at.setter
    def expires_at(self, value: str):
        try:
            # Проверяем формат даты
            expires = datetime.fromisoformat(value)
            created = datetime.fromisoformat(self._created_at) if self._created_at else datetime.now()
            if expires < created:
                raise ValueError("Дата истечения не может быть раньше даты создания")
            self._expires_at = value
        except Exception as e:
            raise KeyValidationError("Неверный формат даты истечения", e)
    
    def to_dict(self) -> Dict[str, str]:
        """Преобразует объект в словарь для сериализации"""
        return {
            "key": self.key,
            "created_at": self.created_at,
            "expires_at": self.expires_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'KeyData':
        """Создает объект из словаря"""
        return cls(
            key=data["key"],
            created_at=data["created_at"],
            expires_at=data["expires_at"]
        )
    
    def is_expired(self) -> bool:
        """Проверяет, истек ли срок действия ключа"""
        return datetime.now() >= datetime.fromisoformat(self.expires_at)
    
    def __str__(self) -> str:
        return f"KeyData(created={self.created_at}, expires={self.expires_at})"


class KeysData:
    """Класс для управления текущим и предыдущим ключами"""
    def __init__(self, current: KeyData, previous: Optional[KeyData] = None):
        """Инициализация данных ключей
        Args: current: Текущий ключ
            previous: Предыдущий ключ (опционально)
        """
        if not isinstance(current, KeyData):
            raise KeyValidationError("current должен быть экземпляром KeyData")
        if previous is not None and not isinstance(previous, KeyData):
            raise KeyValidationError("previous должен быть экземпляром KeyData")
        self.current = current
        self.previous = previous
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразует объект в словарь для сериализации"""
        data = {
            "current_key": self.current.to_dict(),
            "previous_keys": []
        }
        if self.previous:
            data["previous_keys"].append(self.previous.to_dict())
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeysData':
        """Создает объект из словаря"""
        current = KeyData.from_dict(data["current_key"])
        previous = None
        if data.get("previous_keys"):
            previous = KeyData.from_dict(data["previous_keys"][0])
        return cls(current=current, previous=previous)
    
    def should_rotate(self) -> bool:
        """Проверяет, нужно ли выполнить ротацию ключей"""
        return self.current.is_expired()
    
    def rotate(self, new_key: KeyData) -> None:
        """ Выполняет ротацию ключей
        Args: new_key: Новый ключ, который станет текущим
        """
        if not isinstance(new_key, KeyData):
            raise KeyValidationError("new_key должен быть экземпляром KeyData")
        self.previous = self.current
        self.current = new_key
    
    def __str__(self) -> str:
        return f"KeysData(current={self.current}, previous={self.previous})"


class BaseKeyManager:
    def __init__(self, base_dir: str, user_id: int = None):
        self.key_distributor = None
        self.backup_file = None
        self.keys_file = None
        self.base_dir = base_dir
        self.user_id = user_id if user_id is not None else self._extract_user_id(base_dir)
        self.keys_dir = get_user_keys_dir(self.user_id)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        # Устанавливаем права доступа для директории ключей
        set_windows_secure_permissions(self.keys_dir, is_directory=True)
        self.recovery_manager = KeyRecoveryManager(self.user_id, self.keys_dir)
        self.keys_data = None
        self.logger = logger.getChild(f"{self.__class__.__name__}_{self.user_id}")
    
    def _extract_user_id(self, base_dir: str) -> int:
        try:
            # извлечение user_id из пути, подобного 'secure_data/users/num'
            pattern = r'users[/\\](\d+)'
            match = re.search(pattern, str(base_dir))
            if match:
                return int(match.group(1))
            else:
                # Возвращаем user_id 1, если не удалось извлечь
                logger.warning(f"Не удалось извлечь user_id из пути: {base_dir}, используем пользователя по умолчанию (1)")
                return 1
        except Exception as e:
            logger.error(f"Ошибка при извлечении user_id: {str(e)}")
            return 1
    
    def _validate_key_data(self, key_data: KeyData) -> bool:
        """Проверяет валидность данных ключа"""
        try:
            # Проверка формата ключа
            key_bytes = base64.b64decode(key_data.key)
            # Пробуем создать Fernet с этим ключом
            Fernet(key_bytes)
            # Проверка дат
            datetime.fromisoformat(key_data.created_at)
            datetime.fromisoformat(key_data.expires_at)
            return True
        except (TypeError, ValueError, InvalidToken) as e:
            logger.error(f"Ошибка валидации ключа: {str(e)}")
            raise KeyValidationError("Ключ не прошел валидацию", e)

    def _backup_keys(self):
        """Создает резервную копию текущих ключей"""
        try:
            if self.keys_file.exists():
                import shutil
                shutil.copy2(self.keys_file, self.backup_file)
                # Устанавливаем права доступа для резервной копии
                set_windows_secure_permissions(self.backup_file)
        except Exception as e:
            logger.error(f"Ошибка при создании резервной копии ключей: {str(e)}")
            raise KeyBackupError("Не удалось создать резервную копию ключей")

    def _restore_from_backup(self):
        """Восстанавливает ключи из резервной копии"""
        try:
            if self.backup_file.exists():
                import shutil
                shutil.copy2(self.backup_file, self.keys_file)
                return True
        except Exception as e:
            logger.error(f"Ошибка при восстановлении из резервной копии: {str(e)}")
        return False

    def _load_or_create_keys(self):
        """Загружает существующие ключи или создает новые"""
        try:
            if self.keys_file.exists():
                # Создаем резервную копию перед загрузкой
                self._backup_keys()
                
                try:
                    with open(self.keys_file, 'r') as f:
                        data = json.load(f)
                    
                    self.keys_data = KeysData.from_dict(data)
                    # Валидация загруженных ключей
                    if not self._validate_key_data(self.keys_data.current):
                        raise KeyValidationError("Текущий ключ не прошел валидацию")
                        
                    if self.keys_data.previous:
                        try:
                            if not self._validate_key_data(self.keys_data.previous):
                                self.keys_data.previous = None
                                logger.warning("Предыдущий ключ не прошел валидацию и будет пропущен")
                        except KeyValidationError:
                            self.keys_data.previous = None
                            logger.warning("Предыдущий ключ не прошел валидацию и будет пропущен")
                except Exception as e:
                    logger.error(f"Ошибка при загрузке ключей: {str(e)}")
                    if self._restore_from_backup():
                        logger.info("Восстановлено из резервной копии")
                        return
                    else:
                        logger.warning("Не удалось восстановить из резервной копии, создаем новые ключи")
                        self._create_new_keys()
            else:
                logger.info("Файл ключей не найден, создаем новые ключи")
                self._create_new_keys()
        except Exception as e:
            logger.error(f"Ошибка при загрузке/создании ключей: {str(e)}")
            raise KeyManagementError("Не удалось загрузить или создать ключи", e)
    
    def _create_new_keys(self):
        """Создает новые ключи шифрования"""
        try:
            # Генерация нового ключа Fernet
            encryption_key = Fernet.generate_key()
            created_at = datetime.now().isoformat()
            expires_at = (datetime.now() + timedelta(days=30)).isoformat()

            key_data = KeyData(
                key=base64.b64encode(encryption_key).decode('utf-8'),
                created_at=created_at,
                expires_at=expires_at
            )

            # Сохраняем ключи
            self.keys_data = KeysData(current=key_data)
            success = self._save_keys()
            if not success:
                raise KeyCreationError("Не удалось сохранить ключи")

            return key_data
        except Exception as e:
            logger.error(f"Ошибка создания ключа Fernet: {str(e)}")
            raise KeyCreationError("Ошибка создания ключа Fernet", e)
    
    def _save_keys(self):
        """Сохраняет ключи в файл"""
        try:
            # Создаем резервную копию перед сохранением
            if self.keys_file.exists():
                self._backup_keys()
            
            # Сохраняем новые данные
            with open(self.keys_file, 'w') as f:
                json.dump(self.keys_data.to_dict(), f)
            
            # Устанавливаем права доступа
            set_windows_secure_permissions(self.keys_file)
            return True
            
        except Exception as e:
            logger.error(f"Ошибка при сохранении ключей: {str(e)}")
            # Пробуем восстановить из резервной копии
            if not self._restore_from_backup():
                raise KeyManagementError("Не удалось сохранить ключи и восстановить из резервной копии")
    
    def should_rotate_key(self) -> bool:
        return self.keys_data.should_rotate()


class FernetKeyManager(BaseKeyManager):
    def __init__(self, base_dir: str, user_id: int = None):
        super().__init__(base_dir, user_id)
        self.keys_file = self.keys_dir / 'fernet_keys.json'
        self.backup_file = self.keys_dir / 'backup' / 'fernet_keys.json.backup'
        self._load_or_create_keys()

    def _validate_encrypted_data(self, encrypted_data: bytes) -> bool:
        """
        Проверяет, что данные были зашифрованы действующим ключом
        Args: encrypted_data: Зашифрованные данные для проверки
        Returns: bool: True если данные валидны
        Raises: KeyValidationError: если данные зашифрованы недействительным ключом
        """
        try:
            # Проверяем текущий ключ
            current_key = self.get_current_key()
            current_fernet = Fernet(current_key)
            try:
                # Пробуем расшифровать текущим ключом
                current_fernet.decrypt(encrypted_data)
                # Если успешно и ключ действителен, возвращаем True
                if not self.keys_data.current.is_expired():
                    return True
            except Exception:
                pass
            
            # Проверяем предыдущий ключ, если он есть
            if self.keys_data.previous:
                try:
                    previous_key = self.decode_key(self.keys_data.previous.key)
                    previous_fernet = Fernet(previous_key)
                    previous_fernet.decrypt(encrypted_data)
                    
                    # Проверяем, что ключ не истек
                    if not self.keys_data.previous.is_expired():
                        return True
                except Exception:
                    pass
            
            # Если ни один из действующих ключей не подошел
            raise KeyValidationError("Данные зашифрованы недействительным или устаревшим ключом")
        except Exception as e:
            raise KeyValidationError(f"Ошибка при валидации зашифрованных данных: {str(e)}")
    
    def _validate_key_data(self, key_data: KeyData) -> bool:
        try:
            # Проверка формата ключа
            key_bytes = base64.b64decode(key_data.key)
            # Пробуем создать Fernet с этим ключом
            Fernet(key_bytes)
            return True
        except Exception as e:
            logger.error(f"Ошибка валидации ключа Fernet: {str(e)}")
            return False
    
    def _create_new_keys(self):
        try:
            # Генерация нового ключа Fernet
            encryption_key = Fernet.generate_key()
            created_at = datetime.now().isoformat()
            expires_at = (datetime.now() + timedelta(days=30)).isoformat()

            key_data = KeyData(
                key=base64.b64encode(encryption_key).decode('utf-8'),
                created_at=created_at,
                expires_at=expires_at
            )
            # Сохраняем ключи
            self.keys_data = KeysData(current=key_data)
            self._save_keys()

            return key_data
        except Exception as e:
            raise KeyCreationError("Ошибка создания ключа Fernet", e)
    
    def get_current_key(self) -> bytes:
        """Получение текущего ключа"""
        try:
            if not self.keys_data or not self.keys_data.current:
                self._load_or_create_keys()
                
            if not self.keys_data or not self.keys_data.current:
                raise KeyManagementError("Не удалось загрузить или создать ключи")
                
            # Используем локальный ключ
            return base64.b64decode(self.keys_data.current.key)
            
        except Exception as e:
            self.logger.error(f"Ошибка получения текущего ключа: {str(e)}")
            raise KeyManagementError("Ошибка получения ключа")
    
    def get_previous_keys(self) -> list:
        if self.keys_data.previous:
            return [base64.b64decode(self.keys_data.previous.key)]
        return []
    
    def rotate_key(self) -> bool:
        try:
            new_key = Fernet.generate_key()
            new_key_data = KeyData(
                key=base64.b64encode(new_key).decode(),
                created_at=datetime.now().isoformat(),
                expires_at=(datetime.now() + timedelta(days=90)).isoformat()
            )
            self.keys_data.rotate(new_key_data)
            self._save_keys()
            return True
        except Exception as e:
            error = KeyRotationError("Не удалось выполнить ротацию ключа Fernet", e)
            success, message = self.recovery_manager.handle_key_error(error, self.keys_file)
            logger.error(message)
            return False

    def decode_key(self, key_str: str) -> bytes:
        """Декодирует ключ из строки в байты"""
        try:
            return base64.b64decode(key_str)
        except Exception as e:
            self.logger.error(f"Ошибка декодирования ключа: {str(e)}")
            raise KeyManagementError("Ошибка декодирования ключа")


class AESKeyManager(BaseKeyManager):
    def __init__(self, base_dir: str, user_id: int = None):
        super().__init__(base_dir, user_id)
        self.keys_file = self.keys_dir / "aes_keys.json"
        self.backup_file = self.keys_dir / "aes_keys.backup.json"
        self._load_or_create_keys()
    
    def _validate_key_data(self, key_data: KeyData) -> bool:
        try:
            # Проверка формата ключа
            key_bytes = base64.b64decode(key_data.key)
            return len(key_bytes) == 32  # AES-256 ключ
        except Exception as e:
            logger.error(f"Ошибка валидации ключа AES: {str(e)}")
            return False
    
    def _create_new_keys(self):
        """Создает новые ключи шифрования AES"""
        try:
            # Генерация нового ключа AES
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256
                salt=salt,
                iterations=100000,
            )
            encryption_key = kdf.derive(os.urandom(32))
            created_at = datetime.now().isoformat()
            expires_at = (datetime.now() + timedelta(days=30)).isoformat()

            key_data = KeyData(
                key=base64.b64encode(encryption_key).decode('utf-8'),
                created_at=created_at,
                expires_at=expires_at
            )

            # Сохраняем ключи
            self.keys_data = KeysData(current=key_data)
            success = self._save_keys()
            if not success:
                raise KeyCreationError("Не удалось сохранить ключи")

            return key_data
        except Exception as e:
            logger.error(f"Ошибка создания ключа AES: {str(e)}")
            raise KeyCreationError("Ошибка создания ключа AES", e)
    
    def get_current_key(self) -> bytes:
        """Получение текущего ключа"""
        try:
            if not self.keys_data or not self.keys_data.current:
                self._load_or_create_keys()
                
            if not self.keys_data or not self.keys_data.current:
                raise KeyManagementError("Не удалось загрузить или создать ключи")
                
            # Используем локальный ключ
            return base64.b64decode(self.keys_data.current.key)
            
        except Exception as e:
            self.logger.error(f"Ошибка получения текущего ключа: {str(e)}")
            raise KeyManagementError("Ошибка получения ключа")
    
    def get_previous_keys(self) -> list:
        if self.keys_data.previous:
            return [base64.b64decode(self.keys_data.previous.key)]
        return []
    
    def rotate_key(self) -> bool:
        try:
            # Генерация нового ключа AES
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256
                salt=salt,
                iterations=100000,
            )
            new_key = kdf.derive(os.urandom(32))
            new_key_data = KeyData(
                key=base64.b64encode(new_key).decode(),
                created_at=datetime.now().isoformat(),
                expires_at=(datetime.now() + timedelta(days=90)).isoformat()
            )
            self.keys_data.rotate(new_key_data)
            self._save_keys()
            return True
        except Exception as e:
            error = KeyRotationError("Не удалось выполнить ротацию ключа AES", e)
            success, message = self.recovery_manager.handle_key_error(error, self.keys_file)
            logger.error(message)
            return False

    def decode_key(self, key_str: str) -> bytes:
        """Декодирует ключ из строки в байты"""
        try:
            return base64.b64decode(key_str)
        except Exception as e:
            self.logger.error(f"Ошибка декодирования ключа: {str(e)}")
            raise KeyManagementError("Ошибка декодирования ключа")
