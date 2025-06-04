import os
from pathlib import Path
from password_manager.utils.logging_config import setup_logging
from password_manager.security.windows_permissions import set_windows_secure_permissions
from typing import Optional, Dict

logger = setup_logging()

class Config:
    _instances: Dict[Path, 'Config'] = {}
    
    def __new__(cls, base_dir_override: Optional[Path] = None) -> 'Config':
        # Determine the application data path
        app_name = "PasswordManagerKK" # Or your desired app name
        app_data_path = Path(os.getenv('LOCALAPPDATA', '')) / app_name
        
        # Use app_data_path as the key for singleton instances
        if app_data_path not in cls._instances:
            instance = super().__new__(cls)
            instance._initialized = False # Initialize before setting attributes
            
            # The primary base for application data is now app_data_path
            instance.app_data_base_dir = app_data_path
            instance.secure_data_dir = instance.app_data_base_dir / 'secure_data'
            
            # Original base_dir (project root when developing) can be stored for other purposes if needed
            if base_dir_override:
                instance.project_root_dir = Path(base_dir_override).resolve()
            else:
                # This attempts to find the project root, useful for dev-time resources
                # It might not be reliable when bundled, so prefer app_data_base_dir for runtime data
                try:
                    instance.project_root_dir = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))).resolve()
                except NameError: # __file__ is not defined when bundled with PyInstaller sometimes
                    instance.project_root_dir = Path.cwd() # Fallback to current working directory

            instance._ensure_secure_directories()
            
            cls._instances[app_data_path] = instance
        
        return cls._instances[app_data_path]
    
    def __init__(self, base_dir_override: Optional[Path] = None): # Parameter name matches __new__
        if not self._initialized:
            # Initialize paths based on secure_data_dir determined in __new__
            self.database_path = str(self.secure_data_dir / 'passwords.db')
            self.master_password: Optional[str] = None
            self._initialized = True
            logger.info(f"Config initialized. Database path: {self.database_path}")
            logger.info(f"Secure data directory: {self.secure_data_dir}")
            if hasattr(self, 'project_root_dir'):
                 logger.info(f"Project root directory (for dev/resources): {self.project_root_dir}")

    def _ensure_secure_directories(self):
        """Создание и настройка безопасных директорий"""
        try:
            self.secure_data_dir.mkdir(parents=True, exist_ok=True)
            
            set_windows_secure_permissions(self.secure_data_dir, is_directory=True)
            
            logger.info("Защищенные директории успешно созданы (без .keys)")
            
        except Exception as e:
            logger.error(f"Ошибка при создании защищенных директорий: {e}")
            raise

    def set_master_password(self, password: str) -> None:
        """
        Sets the master password (passphrase) for the database.
        """
        if not password:
            logger.warning("Attempted to set an empty master password.")
            # Decide if an empty password should be an error or handled
            # For now, allowing it but logging. DatabaseManager will likely fail.
            # raise ValueError("Master password cannot be empty.")
        self.master_password = password
        # logger.info(f"Master password (passphrase) has been set in Config: '{password[:3]}...'") # Removed for security

    def get_master_password(self) -> Optional[str]:
        """
        Gets the currently set master password (passphrase).
        """
        if self.master_password is None:
            logger.debug("Master password (passphrase) has not been set yet.")
        # else:
            # logger.debug(f"Retrieved master password (passphrase) from Config: '{self.master_password[:3]}...'")
        return self.master_password
            
    @property
    def db_key(self) -> str:
        current_master_password = self.get_master_password()
        if not current_master_password:
            logger.error("Master password (passphrase) is not initialized when accessing db_key!")
            raise ValueError("Master password (passphrase) is not initialized")
        return current_master_password
    
    @classmethod
    def reset(cls):
        cls._instances.clear()
