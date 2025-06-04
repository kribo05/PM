import win32security
import win32file
import win32con
import ntsecuritycon as con
import win32api
from pathlib import Path
import logging
from typing import Union

logger = logging.getLogger(__name__)


def set_windows_secure_permissions(path: Union[str, Path], is_directory: bool = False):
    """
    Установка безопасных прав доступа для файла или директории в Windows
    
    Args:
        path: Путь к файлу или директории
        is_directory: True если это директория, False если файл
    """
    try:
        path = str(path)
        
        # Получаем имя текущего пользователя
        try:
            username = win32api.GetUserName()
            user_sid = win32security.LookupAccountName(None, username)[0]
        except Exception as e:
            logger.error(f"Ошибка при получении данных пользователя: {e}")
            raise PermissionError(f"Не удалось получить данные пользователя: {e}")
        
        # Получаем SID SYSTEM
        system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
        
        # Создаем пустой DACL
        dacl = win32security.ACL()
        
        # Добавляем разрешения для SYSTEM
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,  # Версия ACL
            con.FILE_ALL_ACCESS,  # Права доступа
            system_sid  # SID системного пользователя - идентификатор
        )
        
        # Добавляем разрешения для текущего пользователя
        if is_directory:
            # Для директории даем полный доступ
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                con.FILE_ALL_ACCESS,
                user_sid
            )
        else:
            # Для файла ограничиваем права - список контроля доступа
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,  # Только чтение и запись
                user_sid
            )
        
        # Получаем security descriptor
        security_descriptor = win32security.GetFileSecurity(
            path,
            win32security.DACL_SECURITY_INFORMATION     # Информация о безопасности
        )
        
        # Устанавливаем новый DACL -
        security_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            path,
            win32security.DACL_SECURITY_INFORMATION,
            security_descriptor
        )
        
        # Для файлов устанавливаем дополнительные атрибуты
        if not is_directory:
            win32file.SetFileAttributes(
                path,
                win32con.FILE_ATTRIBUTE_NORMAL
            )
        
        logger.info(f"Установлены безопасные права доступа для: {path}")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка при установке прав доступа Windows: {e}")
        return False

def set_windows_private_key_permissions(path: Union[str, Path]):
    """
    Установка особо защищенных прав доступа для приватных ключей
    Args: path: Путь к файлу ключа
    """
    try:
        path = str(path)
        
        # Получаем имя текущего пользователя
        try:
            username = win32api.GetUserName()
            user_sid = win32security.LookupAccountName(None, username)[0]
        except Exception as e:
            logger.error(f"Ошибка при получении данных пользователя: {e}")
            raise PermissionError(f"Не удалось получить данные пользователя: {e}")

        # Сначала снимаем все атрибуты файла
        try:
            current_attributes = win32file.GetFileAttributes(path)
            win32file.SetFileAttributes(path, win32con.FILE_ATTRIBUTE_NORMAL)
        except Exception as e:
            logger.warning(f"Не удалось сбросить атрибуты файла {path}: {e}")

        # Создаем пустой DACL
        dacl = win32security.ACL()
        
        # Получаем SID SYSTEM
        system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
        
        # Добавляем минимальные права для SYSTEM
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_GENERIC_READ,
            system_sid
        )

        # Добавляем права для текущего пользователя
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
            user_sid
        )
        
        # Получаем security descriptor
        security_descriptor = win32security.GetFileSecurity(
            path,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION
        )
        
        # Устанавливаем владельца файла
        security_descriptor.SetSecurityDescriptorOwner(user_sid, False)
        
        # Устанавливаем новый DACL
        security_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
        
        # Применяем настройки безопасности
        win32security.SetFileSecurity(
            path,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION,
            security_descriptor
        )
        
        # Устанавливаем финальные атрибуты
        try:
            win32file.SetFileAttributes(
                path,
                win32con.FILE_ATTRIBUTE_NORMAL
            )
        except Exception as e:
            logger.warning(f"Не удалось установить финальные атрибуты файла {path}: {e}")
        
        logger.info(f"Установлены защищенные права доступа для приватного ключа: {path}")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка при установке прав доступа для приватного ключа: {e}")
        return False 