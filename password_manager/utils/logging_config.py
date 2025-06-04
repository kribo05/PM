import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional


class LoggerSingleton:
    _instance: Optional[logging.Logger] = None
    _initialized = False

    @classmethod
    def get_logger(cls, log_level=logging.DEBUG) -> logging.Logger:
        """
        Получение единственного экземпляра логгера
        Args:
            log_level: Уровень логирования (по умолчанию: DEBUG)
        Returns:
            logging.Logger: Настроенный логгер
        """
        if not cls._instance or not cls._initialized:
            cls._instance = cls._setup_logging(logging.DEBUG)
            cls._initialized = True
        return cls._instance

    @staticmethod
    def _setup_logging(log_level=logging.DEBUG) -> logging.Logger:
        """
        Настройка конфигурации логирования для менеджера паролей
        Args:
            log_level: Уровень логирования (по умолчанию: DEBUG)
        Returns:
            logging.Logger: Настроенный логгер
        """
        # Получение базовой директории (корень проекта)
        base_dir = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        log_dir = base_dir / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Создание formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        
        # Создание handlers
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(log_level)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / 'password_manager.log',
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(log_level)
        
        # Настройка корневого логгера
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Удаление существующих обработчиков
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Добавление обработчиков
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)
        
        # Создание логгера приложения
        logger = logging.getLogger('password_manager')
        logger.setLevel(log_level)
        
        return logger


def setup_logging(log_level=logging.DEBUG) -> logging.Logger:
    """
    Функция для получения настроенного логгера
    Args: log_level: Уровень логирования (по умолчанию: DEBUG)
    Returns: logging.Logger: Настроенный логгер
    """
    return LoggerSingleton.get_logger(log_level)
