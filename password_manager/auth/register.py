from password_manager.database.database_manager import DatabaseManager
from password_manager.security.password_security import PasswordSecurity
from password_manager.utils.logging_config import setup_logging

logger = setup_logging()


class UserRegistration:
    """
    Обрабатывает логику регистрации пользователя отдельно от UI
    """
    @staticmethod
    def register_user(username: str, password: str) -> bool:
        """
        Регистрирует нового пользователя с указанным именем пользователя и паролем.
        Args: username: Имя пользователя для нового пользователя
            password: Пароль в открытом виде для нового пользователя
        Returns: bool: True, если регистрация прошла успешно, False в противном случае
        """
        try:
            # Проверка надежности пароля
            valid, message = PasswordSecurity.validate_password(password)
            if not valid:
                logger.warning(f"Проверка пароля не удалась: {message}")
                return False
                
            # Регистрация пользователя в базе данных
            db_manager = DatabaseManager()
            success = db_manager.register_user(username, password)
            
            if success:
                logger.info(f"Пользователь '{username}' успешно зарегистрирован")
                return True
            else:
                logger.warning(f"Не удалось зарегистрировать пользователя '{username}' - имя пользователя может уже существовать")
                return False
                
        except Exception as e:
            logger.error(f"Ошибка регистрации: {str(e)}")
            return False
