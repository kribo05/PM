"""
Модуль шифрования для Password Manager.
Предоставляет классы и функции для шифрования и дешифрования данных,
а также для управления ключами шифрования.

Основные компоненты:
- EncryptionService: Основной сервис для работы с шифрованием
- KeyFactory: Фабрика для создания и управления ключами
- CryptoManager: Менеджер криптографических операций
- KeyInitializer: Инициализация ключей для пользователей
"""

# Импорт ключевых классов
from password_manager.encryption.crypto_manager import CryptoManager
from password_manager.encryption.key_factory_class import KeyFactory
from password_manager.encryption.key_initializer import KeyInitializer
from password_manager.encryption.key_manager import FernetKeyManager, AESKeyManager


class EncryptionService:
    """
    Основной сервис для работы с шифрованием. Предоставляет единую точку входа для всех операций шифрования.
    """
    def __init__(self, base_dir=None):
        """
        Инициализирует сервис шифрования.
        Args: base_dir: Базовая директория для хранения ключей. Если None, определяется автоматически.
        """
        self.base_dir = base_dir
        self.key_factory = KeyFactory()
        self.crypto_manager = CryptoManager(base_dir, self.key_factory)
        self.key_initializer = KeyInitializer(base_dir)
    
    def encrypt_password(self, password: str, user_id: int) -> str:
        """
        Шифрует пароль для указанного пользователя.
        Args: password: Пароль для шифрования
            user_id: ID пользователя
        Returns: str: Зашифрованный пароль
        """
        return self.crypto_manager.encrypt_password(password, user_id)
    
    def decrypt_password(self, encrypted_password: str, user_id: int) -> str:
        """
        Расшифровывает пароль для указанного пользователя.
        Args: encrypted_password: Зашифрованный пароль
            user_id: ID пользователя
        Returns: str: Расшифрованный пароль
        """
        result = self.crypto_manager.decrypt_password(encrypted_password, user_id)
        if isinstance(result, tuple):
            # CryptoManager._try_decrypt_with_previous_keys мог вернуть (plaintext, new_encrypted_password)
            # Для данного метода сервиса мы возвращаем только plaintext.
            return result[0]
        return result # result уже является строкой (расшифровано текущим ключом или ошибка, которая будет обработана выше)
    
    def initialize_user_keys(self, user_id: int) -> bool:
        """
        Инициализирует ключи для указанного пользователя.
        Args: user_id: ID пользователя
        Returns: bool: True если инициализация успешна, False в противном случае
        """
        return self.key_initializer.initialize_user_keys(user_id)
    
    def force_create_keys(self, user_id: int) -> tuple[bool, bool]:
        """
        Принудительно создает ключи для указанного пользователя.
        Args: user_id: ID пользователя
        Returns: tuple[bool, bool]: (успех создания Fernet ключей, успех создания AES ключей)
        """
        return self.key_factory.force_create_keys(self.base_dir, user_id)


# Экспорт публичного API
__all__ = [
    'EncryptionService',
]
