import logging
import shutil
from pathlib import Path
from typing import Optional, Tuple
from password_manager.security.exceptions import (
    KeyManagementError,
    KeyCreationError,
    KeyRestoreError,
    KeyBackupError
)
from password_manager.security.windows_permissions import (
    set_windows_secure_permissions,
    set_windows_private_key_permissions
)

logger = logging.getLogger(__name__)


class KeyRecoveryManager:
    """Менеджер для восстановления ключей и обработки ошибок"""
    
    def __init__(self, user_id: int, keys_dir: Path):
        self.user_id = user_id
        self.keys_dir = keys_dir
        self.backup_dir = keys_dir / "backup"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        # Устанавливаем права доступа для директории резервных копий
        set_windows_secure_permissions(self.backup_dir, is_directory=True)
    
    def restore_from_backup(self, key_file: Path) -> bool:
        """Восстанавливает файл ключей из резервной копии"""
        try:
            backup_file = self.backup_dir / f"{key_file.name}.backup"
            if not backup_file.exists():
                logger.warning(f"Резервная копия {backup_file} не существует")
                return False
            
            shutil.copy2(backup_file, key_file)
            
            # Устанавливаем права доступа для восстановленного файла
            if 'private_key' in key_file.name:
                set_windows_private_key_permissions(key_file)
            else:
                set_windows_secure_permissions(key_file)
                
            logger.info(f"Восстановлено из резервной копии {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Ошибка при восстановлении из резервной копии: {str(e)}")
            raise KeyRestoreError(f"Не удалось восстановить из резервной копии {key_file}", e)
    
    def handle_key_error(self, error: KeyManagementError, key_file: Path) -> Tuple[bool, Optional[str]]:
        """
        Обрабатывает ошибки ключей и пытается восстановить систему
        Returns: Tuple[bool, Optional[str]]: (успех восстановления, сообщение для пользователя)
        """
        try:
            error_message = None
            
            if isinstance(error, KeyCreationError):
                # Если ошибка при создании ключей - пробуем восстановить из бэкапа
                if self.restore_from_backup(key_file):
                    error_message = "Произошла ошибка при создании ключей. Восстановлено из резервной копии."
                    return True, error_message
                error_message = "Критическая ошибка: Не удалось создать ключи и восстановить из резервной копии."
            
            elif isinstance(error, KeyBackupError):
                error_message = "Предупреждение: Не удалось создать резервную копию ключей."
                return True, error_message
            
            elif isinstance(error, KeyRestoreError):
                error_message = "Критическая ошибка: Не удалось восстановить ключи из резервной копии."
            
            else:
                error_message = f"Неизвестная ошибка при работе с ключами: {str(error)}"
            
            logger.error(f"Ошибка обработки ключей: {error_message}")
            if error.details:
                logger.error(f"Детали ошибки: {str(error.details)}")
            
            return False, error_message
            
        except Exception as e:
            logger.error(f"Ошибка при обработке ошибки ключей: {str(e)}")
            return False, str(e) 