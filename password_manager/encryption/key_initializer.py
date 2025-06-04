"""
Модуль инициализации ключей для всех пользователей системы.
Запускается при старте приложения.
"""

import logging
from pathlib import Path
from password_manager.encryption.key_factory_class import KeyFactory
from password_manager.encryption.key_manager import FernetKeyManager, AESKeyManager
from password_manager.utils.logging_config import setup_logging
from password_manager.utils.secure_data_utils import get_user_keys_dir
from password_manager.security.windows_permissions import (
    set_windows_secure_permissions,
)
from typing import Optional

logger = logging.getLogger(__name__)


class KeyInitializer:
    """Класс для инициализации ключей шифрования"""
    def __init__(self, base_dir: Optional[str] = None):
        """Инициализация объекта KeyInitializer
        Args: base_dir: Базовый путь к проекту (опционально)
        """
        self.key_factory = KeyFactory()
        self.logger = setup_logging().getChild(self.__class__.__name__)
        self.base_dir = base_dir if base_dir else str(Path(__file__).resolve().parent.parent.parent)
        
    def _initialize_keys_for_user(self, base_dir: str, user_id: int) -> bool:
        """Инициализирует ключи шифрования для конкретного пользователя
        Args: base_dir: Базовая директория проекта
            user_id: ID пользователя
        Returns: bool: True если инициализация успешна, False в противном случае
        """
        from password_manager.security.session import SessionManager # ADDED: Import moved here
        try:
            # Получаем директорию для ключей пользователя
            user_keys_dir = get_user_keys_dir(user_id)
            # Создаем менеджеры ключей
            fernet_manager = FernetKeyManager(base_dir, user_id)
            aes_manager = AESKeyManager(base_dir, user_id)
            session_manager = SessionManager()
            # Проверяем существование ключей
            fernet_exists = fernet_manager.keys_file.exists()
            aes_exists = aes_manager.keys_file.exists()
            # Проверяем существование RSA ключей
            private_key_path = user_keys_dir / 'private_key.pem'
            public_key_path = user_keys_dir / 'public_key.pem'
            rsa_exists = private_key_path.exists() and public_key_path.exists()
            # Создаем резервную директорию
            backup_dir = user_keys_dir / 'backup'
            backup_dir.mkdir(parents=True, exist_ok=True)
            # Устанавливаем права доступа для резервной директории
            try:
                set_windows_secure_permissions(backup_dir, is_directory=True)
            except Exception as e:
                self.logger.warning(f"Не удалось установить права доступа для директории {backup_dir}: {e}")
            
            # Если ключи не существуют, создаем их
            if not fernet_exists:
                self.logger.info("Создание ключей Fernet...")
                fernet_manager._create_new_keys()
                try:
                    if hasattr(fernet_manager, 'keys_file'):
                        set_windows_secure_permissions(fernet_manager.keys_file)
                except Exception as e:
                    self.logger.warning(f"Не удалось установить права доступа для {fernet_manager.keys_file}: {e}")
                
            if not aes_exists:
                self.logger.info("Создание ключей AES...")
                aes_manager._create_new_keys()
                try:
                    if hasattr(aes_manager, 'keys_file'):
                        set_windows_secure_permissions(aes_manager.keys_file)
                except Exception as e:
                    self.logger.warning(f"Не удалось установить права доступа для {aes_manager.keys_file}: {e}")
                
            if not rsa_exists:
                self.logger.info("Создание ключей RSA...")
                # Инициализируем RSA ключи через SessionManager
                # SessionManager._init_user_keys теперь сам сохраняет ключи (приватный - зашифрованно)
                # и создает их резервные копии.
                private_key, public_key = session_manager._init_user_keys(user_id)
                
                # Проверяем, что RSA ключи действительно были созданы SessionManager
                if not private_key_path.exists() or not public_key_path.exists():
                    self.logger.error(f"SessionManager не смог создать/сохранить RSA ключи для пользователя {user_id}")

            
            # Проверяем, что все ключи созданы
            if not all([
                fernet_manager.keys_file.exists(),
                aes_manager.keys_file.exists(),
                private_key_path.exists(),
                public_key_path.exists()
            ]):
                self.logger.error("Не все ключи были успешно созданы")
                return False
            
            self.logger.info(f"Ключи успешно созданы для пользователя {user_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка при инициализации ключей для пользователя {user_id}: {e}")
            return False

    def initialize_user_keys(self, user_id: int) -> bool:
        """ Инициализирует ключи для указанного пользователя.
        Args:user_id: ID пользователя
        Returns: bool: True если инициализация успешна
        """
        try:
            # Очищаем кэш для пользователя
            self.key_factory.clear_key_managers_cache(user_id)
            # Инициализируем ключи
            success = self._initialize_keys_for_user(self.base_dir, user_id)
            if success:
                self.logger.info(f"Ключи успешно инициализированы для пользователя {user_id}")
            else:
                self.logger.error(f"Не удалось инициализировать ключи для пользователя {user_id}")
            return success
            
        except Exception as e:
            self.logger.error(f"Ошибка при инициализации ключей: {str(e)}")
            return False
