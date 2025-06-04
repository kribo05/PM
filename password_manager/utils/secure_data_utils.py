"""
Модуль безопасного хранения данных
Этот модуль обрабатывает безопасное хранение пользовательских данных, резервных копий и ключей шифрования.
"""

import os
from pathlib import Path
import shutil
from password_manager.utils.logging_config import setup_logging
from password_manager.security.windows_permissions import (
    set_windows_secure_permissions,
)

# Initialize logger
logger = setup_logging()


def get_app_secure_data_dir() -> Path:
    """Получение директории для безопасных данных приложения из Config."""
    # Используем Config для получения пути к secure_data_dir в LOCALAPPDATA
    from password_manager.config import Config # <-- ADD THIS LINE HERE
    app_config = Config()
    secure_dir = app_config.secure_data_dir
    # Config.__new__ уже должен был создать эту директорию и установить права
    # secure_dir.mkdir(parents=True, exist_ok=True)
    # set_windows_secure_permissions(secure_dir, is_directory=True)
    # logger.info(f"Secure data directory obtained from Config: {secure_dir}")
    return secure_dir

def get_user_dir(user_id: int) -> Path:
    """Получение директории безопасных данных пользователя."""
    base_secure_dir = get_app_secure_data_dir()
    user_dir = base_secure_dir / "users" / str(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    set_windows_secure_permissions(user_dir, is_directory=True)
    return user_dir

def get_backup_dir(user_id: int) -> Path:
    """Получение директории резервных копий пользователя."""
    # Эта функция, возможно, должна использовать другой base_dir, если бэкапы хранятся отдельно.
    # Пока что оставляем в общей структуре пользователя.
    user_specific_dir = get_user_dir(user_id)
    backup_dir = user_specific_dir / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True) # parents=True на случай, если get_user_dir не вызывался
    set_windows_secure_permissions(backup_dir, is_directory=True)
    return backup_dir

def get_user_secrets_dir(user_id: int) -> Path:
    """Получение директории секретов пользователя для хранения OTP-секретов."""
    user_specific_dir = get_user_dir(user_id)
    secrets_dir = user_specific_dir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    set_windows_secure_permissions(secrets_dir, is_directory=True)
    return secrets_dir

def get_user_keys_dir(user_id: int) -> Path:
    """
    Получает директорию для хранения ключей пользователя.
    Теперь использует app_config.secure_data_dir как базу.
    Args:
        user_id: ID пользователя
    Returns:
        Path: Путь к директории ключей пользователя
    """
    user_specific_dir = get_user_dir(user_id) # Эта функция уже создает users/user_id и ставит права
    user_keys_dir = user_specific_dir / "keys"
    user_keys_dir.mkdir(parents=True, exist_ok=True)
    set_windows_secure_permissions(user_keys_dir, is_directory=True) # Устанавливаем права и на папку keys
    return user_keys_dir

def get_user_qr_path(user_id: int) -> Path:
    """Получение пути к QR-коду пользователя."""
    user_specific_dir = get_user_dir(user_id)
    qr_path = user_specific_dir / "qr.png"
    return qr_path

def ensure_directories_exist(user_id: int) -> None: # Убираем base_dir, так как он теперь берется из Config
    """
    Создает необходимые директории для пользователя (user, keys, backups, secrets).
    Использует пути из Config (LOCALAPPDATA).
    Args:
        user_id: ID пользователя
    """
    logger.info(f"Ensuring directories for user {user_id} using LOCALAPPDATA.")
    # Функции get_*_dir сами создают директории и устанавливают права
    user_dir_path = get_user_dir(user_id)
    keys_dir_path = get_user_keys_dir(user_id)
    backup_dir_path = get_backup_dir(user_id)
    secrets_dir_path = get_user_secrets_dir(user_id)
    
    logger.info(f"Verified/created directories for user {user_id}:")
    logger.info(f"User dir: {user_dir_path}")
    logger.info(f"Keys dir: {keys_dir_path}")
    logger.info(f"Backup dir: {backup_dir_path}")
    logger.info(f"Secrets dir: {secrets_dir_path}")

def secure_delete_file(file_path: Path) -> bool:
    """
    Безопасно удаляет файл, перезаписывая его случайными данными
    Args: file_path: Путь к файлу
    Returns: bool: True если удаление успешно
    """
    try:
        if not file_path.exists():
            return True
            
        # Получаем размер файла
        file_size = file_path.stat().st_size
        
        # Перезаписываем файл случайными данными
        with open(file_path, 'wb') as f:
            # Записываем нули
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
            
            # Записываем единицы
            f.seek(0)
            f.write(b'\xFF' * file_size)
            f.flush()
            os.fsync(f.fileno())
            
            # Записываем случайные данные
            f.seek(0)
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
            
        # Удаляем файл
        os.remove(file_path)
        return True
        
    except Exception as e:
        logger.error(f"Ошибка при безопасном удалении файла: {str(e)}")
        return False

def cleanup_user_data(user_id: int) -> bool:
    """
    Очищает все данные пользователя.
    Использует пути из Config (LOCALAPPDATA).
    Args:
        user_id: ID пользователя
    Returns:
        bool: True если очистка успешна
    """
    logger.info(f"Cleaning up data for user {user_id} from LOCALAPPDATA.")
    try:
        # Получаем директорию пользователя из LOCALAPPDATA
        user_data_root_dir = get_user_dir(user_id)
        # backup_root_dir = get_app_secure_data_dir() / "backups" / str(user_id) # Если бэкапы в другой структуре
        # Для текущей реализации get_backup_dir создает папку backups внутри user_data_root_dir
        
        # Безопасно удаляем все файлы в user_data_root_dir и ее поддиректориях
        if user_data_root_dir.exists():
            for item_path in user_data_root_dir.rglob('*'):
                if item_path.is_file():
                    secure_delete_file(item_path)
            # Удаляем саму директорию пользователя после удаления всех файлов
            shutil.rmtree(user_data_root_dir, ignore_errors=True)
            logger.info(f"Successfully cleaned all data for user {user_id} from {user_data_root_dir}")
        else:
            logger.info(f"User data directory for user {user_id} not found at {user_data_root_dir}. No cleanup needed there.")
            
        return True
        
    except Exception as e:
        logger.error(f"Ошибка при очистке данных пользователя: {str(e)}")
        return False
