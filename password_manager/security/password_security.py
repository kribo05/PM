import re
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from password_manager.utils.logging_config import setup_logging

logger = setup_logging()


class PasswordSecurity:
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=2,  # Количество итераций
            memory_cost=65536,  # Использование памяти в килобайтах
            parallelism=4,  # Количество параллельных потоков
            hash_len=32,  # Длина хеша в байтах
            salt_len=16  # Длина соли в байтах
        )
    
    def hash_password(self, password: str) -> str:
        return self.ph.hash(password)
    
    def verify_password(self, hash: str, password: str) -> bool:
        try:
            if isinstance(hash, bytes):
                hash = hash.decode('utf-8')
            return self.ph.verify(hash, password)
        except (VerifyMismatchError, InvalidHash) as e:
            logger.error(f"Ошибка проверки пароля: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при проверке пароля: {str(e)}")
            return False

    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        if len(password) < 12:
            return False, "Пароль должен содержать не менее 12 символов"

        checks = [
            (r'[A-Z]', "Пароль должен содержать заглавные буквы"),
            (r'[a-z]', "Пароль должен содержать строчные буквы"),
            (r'[0-9]', "Пароль должен содержать цифры"),
            (r'[!@#$%^&*(),.?":{}|<>]', "Пароль должен содержать специальные символы")
        ]

        for pattern, message in checks:
            if not re.search(pattern, password):
                return False, message

        return True, "Пароль соответствует всем требованиям"
