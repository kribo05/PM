from typing import Optional


class SecurityError(Exception):
    """Базовый класс для всех ошибок безопасности"""
    def __init__(self, message: str, details: Optional[Exception] = None):
        self.message = message
        self.details = details
        super().__init__(self.message)


class KeyManagementError(SecurityError):
    """Базовый класс для всех ошибок, связанных с управлением ключами"""
    pass


class KeyCreationError(KeyManagementError):
    """Ошибка при создании ключей"""
    pass


class KeyValidationError(KeyManagementError):
    """Ошибка при валидации ключей"""
    pass


class KeyBackupError(KeyManagementError):
    """Ошибка при работе с резервными копиями ключей"""
    pass


class KeyRestoreError(KeyManagementError):
    """Ошибка при восстановлении ключей"""
    pass


class AuthorizationError(SecurityError):
    """Ошибка авторизации"""
    pass


class EncryptionError(SecurityError):
    """Ошибка шифрования"""
    pass


class DecryptionError(SecurityError):
    """Ошибка расшифрования"""
    pass


class IntegrityError(SecurityError):
    """Ошибка целостности данных"""
    pass


class ConfigurationError(SecurityError):
    """Ошибка конфигурации безопасности"""
    pass


class MasterKeyError(SecurityError):
    """Базовый класс для ошибок, связанных с мастер-ключом"""
    pass


class MasterKeyExistsError(MasterKeyError):
    """Вызывается при попытке создать мастер-ключ, когда он уже существует"""
    pass


class MasterKeyNotFoundError(MasterKeyError):
    """Вызывается, когда мастер-ключ не найден"""
    pass


class MasterKeyCorruptedError(MasterKeyError):
    """Вызывается при обнаружении повреждения мастер-ключа"""
    pass


class InvalidPasswordError(SecurityError):
    """Вызывается при неверном пароле"""
    pass


class KeyIntegrityError(SecurityError):
    """Вызывается при нарушении целостности ключа"""
    pass


class PermissionError(SecurityError):
    """Вызывается при проблемах с правами доступа"""
    pass


class KeyRotationError:
    """Вызывается при проблемах с ротацией ключей"""
    pass