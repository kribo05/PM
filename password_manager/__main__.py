import sys
import tkinter as tk
import logging
from pathlib import Path
from typing import Optional
import os

from password_manager.gui.main_window import MainWindow
from password_manager.database.database_manager import DatabaseManager
from password_manager.utils.logging_config import setup_logging
from password_manager.gui.db_password_dialog import DatabasePasswordDialog
from password_manager.config import Config
from password_manager.encryption import EncryptionService
from password_manager.security.exceptions import KeyManagementError


# Определение исключений на уровне модуля
class ApplicationError(Exception):
    """Базовый класс для ошибок приложения"""
    pass


class InitializationError(ApplicationError):
    """Ошибка инициализации приложения"""
    pass


class DatabaseError(ApplicationError):
    """Ошибка работы с базой данных"""
    pass


class EncryptionError(ApplicationError):
    """Ошибка шифрования"""
    pass


class Application:
    """Основной класс приложения"""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Инициализация приложения
        
        Args:
            config: Конфигурация приложения (опционально)
        """
        self.logger = setup_logging()
        self.config = config or Config()
        self.db_manager = None
        self.root = None
        self.encryption_service = None
        self._is_cleanup_done = False
        
    def _setup_encryption(self) -> None:
        """Настройка сервиса шифрования"""
        try:
            base_dir = os.path.dirname(self.config.database_path)
            self.encryption_service = EncryptionService(base_dir=base_dir)
            self.logger.info("Encryption service configured.")
        except Exception as e:
            raise EncryptionError(f"Ошибка инициализации сервиса шифрования: {str(e)}") from e

    def _setup_database(self) -> None:
        """Настройка менеджера базы данных"""
        try:
            if not self.config.master_password:
                raise DatabaseError("Мастер-пароль (фраза) не инициализирован в Config")
            
            self.db_manager = DatabaseManager(config=self.config)
            self.db_manager.initialize_database()
            self.logger.info("Database manager configured and database initialized.")
        except Exception as e:
            self.logger.error(f"Ошибка настройки базы данных: {str(e)}", exc_info=True)
            raise DatabaseError(f"Ошибка инициализации базы данных: {str(e)}") from e

    def _check_database_password(self) -> bool:
        """
        Запрашивает у пользователя фразу для базы данных и устанавливает ее в Config.
        Возвращает True, если фраза была введена, False, если пользователь отменил.
        Сама проверка корректности фразы произойдет при попытке открыть БД в _setup_database.
        """
        try:
            self.logger.info("Запрос фразы для доступа/создания базы данных...")
            
            # Determine if this is effectively a 'new key' scenario (i.e., database doesn't exist)
            db_path = Path(self.config.database_path)
            is_creating_new_db = not db_path.exists()
            if is_creating_new_db:
                self.logger.info(f"Database file not found at {db_path}. Assuming new database creation.")
            else:
                self.logger.info(f"Database file found at {db_path}. Assuming opening existing database.")

            db_passphrase = DatabasePasswordDialog.get_password(self.root, is_new_key=is_creating_new_db)
            
            if not db_passphrase:
                self.logger.warning("Пользователь отменил ввод фразы базы данных.")
                return False
            
            self.config.set_master_password(db_passphrase)
            self.logger.info("Фраза базы данных принята и установлена в Config.")
            return True
            
        except Exception as e:
            self.logger.error(f"Неожиданная ошибка при запросе фразы базы данных: {str(e)}", exc_info=True)
            return False

    def _initialize_user_encryption(self) -> None:
        """Инициализация ключей шифрования для всех пользователей"""
        try:
            self.logger.info("Инициализация ключей шифрования для всех пользователей...")
            if not self.db_manager:
                self.logger.error("db_manager не инициализирован перед _initialize_user_encryption")
                raise EncryptionError("Менеджер БД не готов для инициализации ключей шифрования.")

            with self.db_manager as cur:
                cur.execute("SELECT id FROM Users")
                user_ids = [row[0] for row in cur.fetchall()]
            
            if not user_ids:
                self.logger.info("Пользователи не найдены, пропускаем инициализацию ключей шифрования.")
                return

            failed_users = []
            for user_id in user_ids:
                try:
                    success = self.encryption_service.initialize_user_keys(user_id)
                    if success:
                        self.logger.info(f"Ключи шифрования для пользователя {user_id} инициализированы.")
                    else:
                        self.logger.warning(f"Не удалось инициализировать ключи для пользователя {user_id} (encryption_service вернул False).")
                        failed_users.append(user_id)
                except KeyManagementError as e:
                    self.logger.error(f"Ошибка KeyManagementError при инициализации ключей для пользователя {user_id}: {str(e)}")
                    failed_users.append(user_id)
                except Exception as e:
                    self.logger.error(f"Общая ошибка при инициализации ключей для пользователя {user_id}: {str(e)}", exc_info=True)
                    failed_users.append(user_id)
            
            if failed_users:
                self.logger.error(f"Не удалось инициализировать ключи для следующих пользователей: {failed_users}")
                
        except Exception as e:
            self.logger.error(f"Общая ошибка при _initialize_user_encryption: {str(e)}", exc_info=True)
            raise EncryptionError(f"Ошибка инициализации ключей шифрования: {str(e)}") from e

    def initialize(self) -> bool:
        """
        Инициализация всех компонентов приложения
        Returns: bool: True если инициализация успешна, False в противном случае
        Raises: InitializationError: если произошла критическая ошибка при инициализации
        """
        try:
            self.logger.info("Начало инициализации приложения...")
            
            self.root = tk.Tk()
            self.root.withdraw()
            
            if not self._check_database_password():
                self.logger.warning("Инициализация отменена пользователем (не введена фраза БД).")
                self.cleanup()
                return False
            
            self._setup_database()
            self._setup_encryption()
            self._initialize_user_encryption()
            
            self.logger.info("Инициализация приложения завершена успешно.")
            return True
            
        except InitializationError:
            raise
        except (DatabaseError, EncryptionError) as e:
            self.logger.error(f"Ошибка инициализации приложения: {str(e)}", exc_info=True)
            raise InitializationError(str(e)) from e
        except Exception as e:
            self.logger.error(f"Неожиданная ошибка при инициализации приложения: {str(e)}", exc_info=True)
            raise InitializationError(f"Неожиданная ошибка: {str(e)}") from e
        finally:
            if hasattr(self, 'root') and self.root:
                try:
                    pass
                except Exception as e:
                    self.logger.warning(f"Ошибка при попытке предварительной очистки root в initialize: {e}")

    def cleanup(self) -> None:
        """Очистка ресурсов приложения"""
        if self._is_cleanup_done:
            return
        self.logger.debug("Выполняется очистка ресурсов приложения...")
        try:
            if self.root:
                try:
                    self.root.destroy()
                    self.logger.debug("Временное окно Tkinter (root) уничтожено.")
                except Exception as e:
                    self.logger.warning(f"Ошибка при закрытии временного окна Tkinter (root): {str(e)}")
            self.db_manager = None
            self.logger.debug("Ресурсы db_manager очищены (установлены в None).")
        except Exception as e:
            self.logger.error(f"Ошибка при очистке ресурсов: {str(e)}")
        finally:
            self._is_cleanup_done = True
            self.logger.info("Очистка ресурсов приложения завершена.")

    def run(self) -> None:
        """
        Запуск приложения
        Raises: ApplicationError: если произошла ошибка во время работы приложения
        """
        initialization_successful = False
        try:
            if not self.initialize():
                self.logger.warning("Запуск приложения прерван из-за неудачной инициализации.")
                return
            
            initialization_successful = True
            self.logger.info("Переход к запуску основного окна приложения...")
            
            app = MainWindow()
            app.mainloop()
            
        except ApplicationError:
            raise
        except Exception as e:
            self.logger.critical(f"Неожиданная критическая ошибка во время выполнения приложения: {str(e)}", exc_info=True)
            raise ApplicationError(f"Критическая ошибка приложения: {str(e)}") from e
        finally:
            if initialization_successful:
                self.logger.info("Приложение завершает работу.")
            self.cleanup()


def main() -> None:
    """Точка входа в приложение"""
    app_instance = None
    try:
        app_instance = Application()
        app_instance.run()
        sys.exit(0)  # 0 - код успешного завершения
    except ApplicationError as e:
        logging.getLogger(__name__).critical(f"Критическая ошибка приложения (ApplicationError): {str(e)}")
        if e.__cause__:
            logging.getLogger(__name__).critical(f"  Причина: {type(e.__cause__).__name__}: {str(e.__cause__)}")
        sys.exit(1)
    except Exception as e:
        logging.getLogger(__name__).critical(f"Непредвиденная критическая ошибка на верхнем уровне: {str(e)}", exc_info=True)
        sys.exit(1) # 1 - код ошибки


if __name__ == "__main__":
    main()
