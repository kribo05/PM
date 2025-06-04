import logging
import os
from pathlib import Path
from typing import Tuple, Dict, Optional

from password_manager.encryption.key_manager import FernetKeyManager, AESKeyManager
from password_manager.utils.secure_data_utils import get_user_keys_dir
from password_manager.security.windows_permissions import set_windows_secure_permissions

# Initialize logger at module level
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KeyFactory:
    """ Фабрика ключей шифрования - централизованно управляет всеми ключами шифрования """
    def __init__(self):
        """Инициализирует фабрику ключей с пустым кэшем менеджеров"""
        self.key_managers_cache: Dict[int, Tuple[FernetKeyManager, AESKeyManager]] = {}

    def _ensure_directory_permissions(self, directory: Path) -> None:
        """ Проверяет и устанавливает правильные разрешения для директории
        Args: directory: Путь к директории
        """
        try:
            # Создаем директорию, если она не существует
            os.makedirs(directory, exist_ok=True)
            set_windows_secure_permissions(directory, is_directory=True)
                
            logger.info(f"Установлены правильные разрешения для директории: {directory}")
        except Exception as e:
            logger.error(f"Ошибка при установке разрешений для директории {directory}: {e}")
            raise

    def get_key_managers(self, base_dir: str, user_id: int) -> Tuple[FernetKeyManager, AESKeyManager]:
        """ Получить экземпляры обоих менеджеров ключей для конкретного пользователя.
        Args:base_dir: Базовая директория проекта
            user_id: ID пользователя
        Returns:Tuple[FernetKeyManager, AESKeyManager]: Кортеж из двух менеджеров ключей
        """
        try:
            # Проверяем кэш
            if user_id in self.key_managers_cache:
                return self.key_managers_cache[user_id]
            # Создаем и проверяем директории
            keys_dir = get_user_keys_dir(user_id)
            self._ensure_directory_permissions(keys_dir)
            # Создаем менеджеры
            fernet_manager = FernetKeyManager(base_dir, user_id)
            aes_manager = AESKeyManager(base_dir, user_id)
            # Проверяем существование ключей
            if not fernet_manager.keys_file.exists() or not aes_manager.keys_file.exists():
                fernet_created, aes_created = self.force_create_keys(base_dir, user_id)
                
                if not fernet_created or not aes_created:
                    raise Exception("Не удалось создать необходимые ключи")
                    
                # Пересоздаем менеджеры после создания ключей
                fernet_manager = FernetKeyManager(base_dir, user_id)
                aes_manager = AESKeyManager(base_dir, user_id)
            
            # Сохраняем в кэше
            self.key_managers_cache[user_id] = (fernet_manager, aes_manager)
            
            logger.info(f"Успешно созданы менеджеры ключей для user_id={user_id}")
            return fernet_manager, aes_manager
            
        except Exception as e:
            logger.error(f"Ошибка при получении менеджеров ключей: {e}")
            raise
    
    def clear_key_managers_cache(self, user_id: Optional[int] = None) -> None:
        """Очистить кэш менеджеров ключей"""
        try:
            if user_id is None:
                self.key_managers_cache.clear()
                logger.info("Очищен весь кэш менеджеров ключей")
            elif user_id in self.key_managers_cache:
                del self.key_managers_cache[user_id]
                logger.info(f"Очищен кэш менеджеров ключей для user_id={user_id}")
        except Exception as e:
            logger.error(f"Ошибка при очистке кэша: {e}")
    
    def force_create_keys(self, base_dir: str, user_id: int) -> Tuple[bool, bool]:
        """Принудительно создать оба типа ключей для пользователя"""
        try:
            # Очищаем кэш
            self.clear_key_managers_cache(user_id)
            # Получаем и проверяем директорию ключей
            keys_dir = get_user_keys_dir(user_id)
            self._ensure_directory_permissions(keys_dir)
            # Создаем менеджеры
            fernet_manager = FernetKeyManager(base_dir, user_id)
            aes_manager = AESKeyManager(base_dir, user_id)
            
            fernet_created = False
            aes_created = False
            
            # Создаем Fernet ключи с повторными попытками
            for attempt in range(3):
                try:
                    if not fernet_manager.keys_file.exists():
                        fernet_manager._create_new_keys()
                        fernet_created = fernet_manager.keys_file.exists()
                        if fernet_created:
                            logger.info(f"Созданы Fernet ключи для user_id={user_id} (попытка {attempt + 1})")
                            break
                    else:
                        fernet_created = True
                        break
                except Exception as e:
                    logger.error(f"Ошибка создания Fernet ключей (попытка {attempt + 1}): {e}")
                    
            # Создаем AES ключи с повторными попытками
            for attempt in range(3):
                try:
                    if not aes_manager.keys_file.exists():
                        aes_manager._create_new_keys()
                        aes_created = aes_manager.keys_file.exists()
                        if aes_created:
                            logger.info(f"Созданы AES ключи для user_id={user_id} (попытка {attempt + 1})")
                            break
                    else:
                        aes_created = True
                        break
                except Exception as e:
                    logger.error(f"Ошибка создания AES ключей (попытка {attempt + 1}): {e}")
            
            if not fernet_created or not aes_created:
                logger.error(f"Не удалось создать все необходимые ключи: fernet={fernet_created}, aes={aes_created}")
            
            return fernet_created, aes_created
            
        except Exception as e:
            logger.error(f"Критическая ошибка при создании ключей: {e}")
            return False, False
