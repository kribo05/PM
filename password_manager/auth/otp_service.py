import logging
import pyotp
import qrcode
from pathlib import Path
from password_manager.encryption.key_manager import FernetKeyManager
from cryptography.fernet import Fernet
from password_manager.utils.secure_data_utils import get_user_dir, get_user_secrets_dir, ensure_directories_exist, get_user_qr_path
from password_manager.security.windows_permissions import set_windows_secure_permissions
import platform

logger = logging.getLogger(__name__)


class OTPService:
    def __init__(self, base_dir: str, user_id: int = None):
        self.base_dir = Path(base_dir)
        self.user_id = user_id
        self.key_manager = FernetKeyManager(str(self.base_dir), user_id)
        logger.info(f"OTPService инициализирован с base_dir: {self.base_dir}, user_id: {user_id}")
    
    def generate_backup_otp(self, user_id: int, username: str) -> tuple[str, str]:
        """Генерация OTP специально для управления резервными копиями"""
        try:
            # Обновление внутреннего user_id при необходимости
            if self.user_id is None or self.user_id != user_id:
                self.user_id = user_id
                self.key_manager = FernetKeyManager(str(self.base_dir), user_id)
            # Убедимся, что все директории существуют
            ensure_directories_exist(user_id)
            # Проверяем, настроен ли уже OTP
            if self.is_otp_enabled(user_id):
                logger.warning(f"Резервный OTP уже включен для пользователя {user_id}")
                return "", ""
            # Получаем директории пользователя
            user_dir = get_user_dir(user_id)
            secrets_dir = get_user_secrets_dir(user_id)
            qr_path = get_user_qr_path(user_id)
            logger.info(f"Генерация резервного OTP для пользователя {user_id}")
            logger.info(f"Директория пользователя: {user_dir}")
            logger.info(f"Директория секретов: {secrets_dir}")
            logger.info(f"Путь к QR-коду: {qr_path}")
            # Генерация секретного ключа
            secret = pyotp.random_base32()
            # Создание URI OTP
            totp = pyotp.TOTP(secret, interval=60)
            uri = totp.provisioning_uri(username, issuer_name="Password Manager Backup")
            # Генерация QR-кода
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(uri)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            # Сохранение QR-кода в директории пользователя
            qr_img.save(str(qr_path))
            if platform.system() == "Windows":
                set_windows_secure_permissions(str(qr_path), is_directory=False)
            # сохранение секретного ключа
            self._save_user_secret(user_id, secret)
            logger.info(f"Успешно сгенерирован резервный OTP для пользователя {user_id}")
            return secret, str(qr_path)
            
        except Exception as e:
            logger.error(f"Не удалось сгенерировать резервный OTP: {str(e)}")
            return "", ""
    
    def _save_user_secret(self, user_id: int, secret: str):
        try:
            # Обновление key_manager, если изменился user_id
            if self.user_id is None or self.user_id != user_id:
                self.user_id = user_id
                self.key_manager = FernetKeyManager(str(self.base_dir), user_id)
                
            key = self.key_manager.get_current_key()
            f = Fernet(key)
            encrypted_secret = f.encrypt(secret.encode())
            secret_file = get_user_secrets_dir(user_id) / "backup_secret.enc"
            secret_file.write_bytes(encrypted_secret)
            if platform.system() == "Windows":
                set_windows_secure_permissions(str(secret_file), is_directory=False)
            logger.info(f"Успешно сохранен секретный ключ резервного OTP для пользователя {user_id}")
        except Exception as e:
            logger.error(f"Не удалось сохранить секретный ключ резервного OTP: {str(e)}")
            raise
    
    def verify_backup_otp(self, user_id: int, otp_code: str) -> bool:
        """Проверка OTP кода"""
        try:
            # Обновление key_manager, если изменился user_id
            if self.user_id is None or self.user_id != user_id:
                self.user_id = user_id
                self.key_manager = FernetKeyManager(str(self.base_dir), user_id)
                
            secret_file = get_user_secrets_dir(user_id) / "backup_secret.enc"
            if not secret_file.exists():
                logger.warning(f"Файл секретного ключа резервного OTP не найден для пользователя {user_id}")
                return False
            
            encrypted_secret = secret_file.read_bytes()
            key = self.key_manager.get_current_key()
            f = Fernet(key)
            secret = f.decrypt(encrypted_secret).decode()
            totp = pyotp.TOTP(secret, interval=60)
            return totp.verify(otp_code)
        except Exception as e:
            logger.error(f"Не удалось проверить резервный OTP: {str(e)}")
            return False

    def is_otp_enabled(self, user_id: int) -> bool:
        """Проверка, включен ли OTP для пользователя"""
        secret_file = get_user_secrets_dir(user_id) / "backup_secret.enc"
        return secret_file.exists()
    
    def get_qr_path(self, user_id: int) -> str:
        """Получение пути к QR-коду пользователя"""
        qr_path = get_user_qr_path(user_id)
        return str(qr_path) if qr_path.exists() else ""
    
    def cleanup_otp_files(self, user_id: int):
        """Очистка файлов, связанных с OTP"""
        try:
            qr_path = get_user_qr_path(user_id)
            if qr_path.exists():
                qr_path.unlink()
                logger.info(f"Очищен QR-код для пользователя {user_id}")
        except Exception as e:
            logger.error(f"Не удалось очистить файлы OTP: {str(e)}")
    
    def reset_otp(self, user_id: int):
        """Сброс OTP для пользователя"""
        try:
            # Очистка существующих файлов
            self.cleanup_otp_files(user_id)
            
            # Удаление файла секретного ключа
            secret_file = get_user_secrets_dir(user_id) / "backup_secret.enc"
            if secret_file.exists():
                secret_file.unlink() # Удаление файла из файловой системы
                logger.info(f"Сброшен OTP для пользователя {user_id}")
        except Exception as e:
            logger.error(f"Не удалось сбросить OTP: {str(e)}")
