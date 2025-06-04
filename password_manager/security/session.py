import json
import os
import secrets
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Tuple, List
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from password_manager.security.exceptions import (
    KeyCreationError,
    SecurityError)
from password_manager.security.auto_logout import AutoLogoutManager
from password_manager.security.windows_permissions import (
    set_windows_secure_permissions,
    set_windows_private_key_permissions
)
from password_manager.utils.logging_config import setup_logging
from password_manager.utils.secure_data_utils import get_user_keys_dir
from password_manager.encryption.key_factory_class import KeyFactory


class SessionError(SecurityError):
    """Базовый класс для ошибок сессии"""
    pass


class SessionValidationError(SessionError):
    """Ошибка валидации сессии"""
    def __init__(self, message: str, details: Optional[Exception] = None):
        super().__init__(message)
        self.details = details


class SessionExpiredError(SessionError):
    """Ошибка истекшей сессии"""
    pass


class SessionCreationError(SessionError):
    """Ошибка создания сессии"""
    def __init__(self, message: str, details: Optional[Exception] = None):
        super().__init__(message)
        self.details = details


class SessionRefreshError(SessionError):
    """Ошибка обновления сессии"""
    def __init__(self, message: str, details: Optional[Exception] = None):
        super().__init__(message)
        self.details = details


class RateLimitError(SessionError):
    """Ошибка превышения лимита запросов"""
    pass


class SessionManager:
    def __init__(self, session_duration: int = 120, refresh_token_duration: int = 1440):
        """ Инициализация менеджера сессий
        Args: session_duration: Продолжительность сессии в минутах
            refresh_token_duration: Продолжительность refresh token в минутах (по умолчанию 24 часа)
        """
        self.logger = setup_logging()
        self.logger.info(f"SessionManager initialized with duration: {session_duration} minutes")
        self.session_duration = timedelta(minutes=session_duration)
        self.refresh_token_duration = timedelta(minutes=refresh_token_duration)
        self.active_sessions: Dict[str, dict] = {}
        self.refresh_tokens: Dict[str, dict] = {}
        self.key_factory = KeyFactory()
        # Базовая директория для ключей пользователей
        self.base_keys_dir = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        # Инициализация менеджера автоматического выхода
        self.auto_logout = AutoLogoutManager(timeout_seconds=session_duration * 60)
        # Параметры безопасности
        self.cleanup_interval = 300  # 5 минут
        self.max_refresh_attempts = 5  # Максимальное количество попыток обновления в течение периода
        self.refresh_attempt_window = 3600  # 1 час
        self.refresh_attempts: Dict[int, List[datetime]] = {}  # user_id -> list of attempt timestamps
        # Rate limiting для создания сессий
        self.session_creation_limit = 10  # Максимальное количество сессий в минуту
        self.session_creation_window = 60  # Окно в секундах
        self.session_creation_attempts: Dict[int, List[datetime]] = {}
        # Флаг для контроля работы cleanup thread
        self._shutdown_flag = threading.Event()
        # Запуск очистки
        self._start_cleanup_thread()
        self.logger.info("SessionManager initialized with duration: %d minutes", session_duration)
    
    def shutdown(self):
        """Корректное завершение работы менеджера сессий"""
        self.logger.info("Shutting down SessionManager...")
        self._shutdown_flag.set()
        if hasattr(self, 'cleanup_thread'):
            self.cleanup_thread.join(timeout=5)
        self.logger.info("SessionManager shutdown complete")
    
    def _start_cleanup_thread(self):
        """Запуск потока очистки"""
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_expired_sessions(self):
        """Очистка устаревших сессий и refresh токенов"""
        while not self._shutdown_flag.is_set():
            try:
                current_time = datetime.utcnow()
                
                # Очистка устаревших сессий
                expired_sessions = [
                    token for token, data in list(self.active_sessions.items())
                    if current_time > data['expires']
                ]
                for token in expired_sessions:
                    self.invalidate_session(token)
                
                # Очистка устаревших refresh токенов
                expired_refresh = [
                    token for token, data in list(self.refresh_tokens.items())
                    if current_time > data['expires']
                ]
                for token in expired_refresh:
                    del self.refresh_tokens[token]
                
                # Очистка истории попыток обновления и создания сессий
                self._cleanup_attempts(current_time)
                
                if expired_sessions or expired_refresh:
                    self.logger.debug(f"Очищено {len(expired_sessions)} сессий и {len(expired_refresh)} refresh токенов")
                    
            except Exception as e:
                self.logger.error(f"Ошибка в процессе очистки: {str(e)}")
            
            # Уменьшаем интервал очистки для более быстрого реагирования
            self._shutdown_flag.wait(timeout=1)  # Проверяем каждую секунду вместо 5 минут
    
    def _cleanup_attempts(self, current_time: datetime):
        """Очистка истории попыток обновления и создания сессий"""
        # Очистка попыток обновления
        for user_id in list(self.refresh_attempts.keys()):
            self.refresh_attempts[user_id] = [
                timestamp for timestamp in self.refresh_attempts[user_id]
                if current_time - timestamp < timedelta(seconds=self.refresh_attempt_window)
            ]
            if not self.refresh_attempts[user_id]:
                del self.refresh_attempts[user_id]
        
        # Очистка попыток создания сессий
        for user_id in list(self.session_creation_attempts.keys()):
            self.session_creation_attempts[user_id] = [
                timestamp for timestamp in self.session_creation_attempts[user_id]
                if current_time - timestamp < timedelta(seconds=self.session_creation_window)
            ]
            if not self.session_creation_attempts[user_id]:
                del self.session_creation_attempts[user_id]

    def _check_session_creation_limit(self, user_id: int) -> bool:
        """Проверка ограничения на создание новых сессий"""
        current_time = datetime.utcnow()
        if user_id not in self.session_creation_attempts:
            self.session_creation_attempts[user_id] = []
        
        # Очистка старых попыток
        self.session_creation_attempts[user_id] = [
            timestamp for timestamp in self.session_creation_attempts[user_id]
            if current_time - timestamp < timedelta(seconds=self.session_creation_window)
        ]
        
        # Проверка лимита
        if len(self.session_creation_attempts[user_id]) >= self.session_creation_limit:
            return False
        
        # Добавление новой попытки
        self.session_creation_attempts[user_id].append(current_time)
        return True

    def _get_current_aes_key_for_user(self, user_id: int) -> Optional[bytes]:
        """Получает текущий ключ AES для шифрования/дешифрования приватного ключа RSA."""
        try:
            project_base_dir = str(self.base_keys_dir)
            _, aes_manager = self.key_factory.get_key_managers(project_base_dir, user_id)
            if aes_manager and aes_manager.keys_data and aes_manager.keys_data.current:
                return aes_manager.get_current_key() # Возвращает байты
            self.logger.warning(f"Не удалось получить текущий AES ключ для пользователя {user_id}")
            return None
        except Exception as e:
            self.logger.error(f"Ошибка при получении текущего AES ключа для пользователя {user_id}: {e}")
            return None

    def _get_previous_aes_keys_for_user(self, user_id: int) -> List[bytes]:
        """Получает список предыдущих ключей AES для пользователя."""
        try:
            project_base_dir = str(self.base_keys_dir)
            _, aes_manager = self.key_factory.get_key_managers(project_base_dir, user_id)
            if aes_manager:
                previous_key_list = aes_manager.get_previous_keys() # Это уже список байт
                return previous_key_list
            return []
        except Exception as e:
            self.logger.error(f"Ошибка при получении предыдущих AES ключей для пользователя {user_id}: {e}")
            return []

    def _get_user_keys_dir(self, user_id: int) -> Path:
        """Получение директории для ключей конкретного пользователя"""
        return get_user_keys_dir(user_id)


    def _save_user_keys(self, user_id: int, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey) -> None:
        """ Сохраняет RSA ключи пользователя (приватный и публичный) и их резервные копии.
        Args: user_id: ID пользователя.
            private_key: Приватный ключ RSA.
            public_key: Публичный ключ RSA.
        """
        try:
            user_keys_dir = self._get_user_keys_dir(user_id)
            user_keys_dir.mkdir(parents=True, exist_ok=True)

            private_key_path = user_keys_dir / "private_key.pem"
            public_key_path = user_keys_dir / "public_key.pem"

            aes_key_bytes = self._get_current_aes_key_for_user(user_id)
            if not aes_key_bytes:
                self.logger.error(f"Не удалось получить AES ключ для шифрования приватного ключа RSA пользователя {user_id}.")
                raise KeyCreationError(f"AES ключ не найден для шифрования приватного ключа RSA пользователя {user_id}.")

            # Сохранение приватного ключа
            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(aes_key_bytes)
                ))
            self._set_key_file_permissions(private_key_path)
            self.logger.info(f"Приватный ключ сохранен (зашифрован AES) для пользователя {user_id} в {private_key_path}")

            # Сохранение публичного ключа (публичные ключи обычно не шифруют)
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            self._set_key_file_permissions(public_key_path)
            self.logger.info(f"Публичный ключ сохранен для пользователя {user_id} в {public_key_path}")

            # Создание резервных копий
            backup_dir = user_keys_dir / "backup"
            backup_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            private_key_backup_path = backup_dir / f"private_key_{timestamp}.pem.backup"
            public_key_backup_path = backup_dir / f"public_key_{timestamp}.pem.backup"

            with open(private_key_backup_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(aes_key_bytes)
                ))
            self._set_key_file_permissions(private_key_backup_path)
            self.logger.info(f"Резервная копия приватного ключа сохранена (зашифрована AES) в {private_key_backup_path}")
            
            with open(public_key_backup_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            self._set_key_file_permissions(public_key_backup_path)
            self.logger.info(f"Резервная копия публичного ключа сохранена в {public_key_backup_path}")

        except Exception as e:
            self.logger.error(f"Ошибка при сохранении ключей для пользователя {user_id}: {e}")
            raise KeyCreationError(f"Ошибка сохранения ключей для пользователя {user_id}: {e}")

    def _init_user_keys(self, user_id: int) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """ Инициализирует и сохраняет RSA ключи для пользователя.
        Если ключи уже существуют, они не перезаписываются (для предотвращения случайной потери).
        Чтобы принудительно создать новые ключи, существующие файлы должны быть удалены вручную.
        Args: user_id: ID пользователя
        Returns: Tuple[RSAPrivateKey, RSAPublicKey]: Пара ключей RSA
        """
        try:
            user_keys_dir = self._get_user_keys_dir(user_id)
            private_key_path = user_keys_dir / "private_key.pem"
            public_key_path = user_keys_dir / "public_key.pem"

            if private_key_path.exists() and public_key_path.exists():
                self.logger.info(f"Ключи для пользователя {user_id} уже существуют. Загрузка существующих ключей.")
                loaded_private_key = None
                key_re_saved_after_decryption = False

                # Attempt 1: Try with current AES key
                current_aes_key = self._get_current_aes_key_for_user(user_id)
                if current_aes_key:
                    try:
                        with open(private_key_path, "rb") as f:
                            loaded_private_key = serialization.load_pem_private_key(
                                f.read(),
                                password=current_aes_key,
                                backend=default_backend()
                            )
                        self.logger.info(f"Приватный ключ RSA успешно загружен с использованием текущего ключа AES для пользователя {user_id}.")
                    except (ValueError, TypeError) as e:
                        self.logger.warning(f"Не удалось загрузить приватный ключ RSA с текущим ключом AES для пользователя {user_id}: {e}. Попытка с предыдущими ключами.")
                        loaded_private_key = None
                else:
                    self.logger.warning(f"Текущий ключ AES не найден для пользователя {user_id} при попытке загрузки приватного ключа RSA.")

                # Attempt 2: Try with previous AES keys if not loaded
                if not loaded_private_key:
                    previous_aes_keys = self._get_previous_aes_keys_for_user(user_id)
                    if previous_aes_keys:
                        for prev_aes_key in previous_aes_keys:
                            try:
                                with open(private_key_path, "rb") as f:
                                    loaded_private_key = serialization.load_pem_private_key(
                                        f.read(),
                                        password=prev_aes_key,
                                        backend=default_backend()
                                    )
                                self.logger.info(f"Приватный ключ RSA успешно загружен с использованием предыдущего ключа AES для пользователя {user_id}.")
                                with open(public_key_path, "rb") as f_pub_val:
                                    public_key_val = serialization.load_pem_public_key(f_pub_val.read(), backend=default_backend())
                                self._save_user_keys(user_id, loaded_private_key, public_key_val)
                                key_re_saved_after_decryption = True
                                self.logger.info(f"Приватный ключ RSA пересохранен с текущим ключом AES для пользователя {user_id} после дешифровки старым ключом.")
                                break 
                            except (ValueError, TypeError):
                                self.logger.debug(f"Не удалось загрузить приватный ключ RSA с одним из предыдущих ключей AES для пользователя {user_id}.")
                                continue
                        if not loaded_private_key:
                            self.logger.warning(f"Не удалось загрузить приватный ключ RSA ни с одним из предыдущих ключей AES для пользователя {user_id}.")
                    else:
                        self.logger.info(f"Список предыдущих AES ключей пуст для пользователя {user_id}.")


                # Attempt 3: Try with no password (for unencrypted keys from before this change)
                if not loaded_private_key:
                    try:
                        with open(private_key_path, "rb") as f:
                            loaded_private_key = serialization.load_pem_private_key(
                                f.read(),
                                password=None, # Trying with no password
                                backend=default_backend()
                            )
                        self.logger.info(f"Приватный ключ RSA успешно загружен без пароля (вероятно, старый нешифрованный формат) для пользователя {user_id}.")
                        with open(public_key_path, "rb") as f_pub_val:
                            public_key_val = serialization.load_pem_public_key(f_pub_val.read(), backend=default_backend())
                        self._save_user_keys(user_id, loaded_private_key, public_key_val)
                        key_re_saved_after_decryption = True
                        self.logger.info(f"Нешифрованный приватный ключ RSA пересохранен с текущим ключом AES для пользователя {user_id}.")
                    except (ValueError, TypeError) as e:
                        self.logger.error(f"Не удалось загрузить приватный ключ RSA без пароля для пользователя {user_id} после неудачных попыток с AES ключами: {e}. Это может означать, что ключ поврежден или зашифрован неизвестным паролем.")
                        # All attempts failed
                        raise KeyCreationError(f"Не удалось загрузить приватный ключ RSA для пользователя {user_id} ни одним из методов (AES текущий/предыдущие, без пароля). Ключ может быть поврежден.")

                if not loaded_private_key:
                     raise KeyCreationError(f"Критическая ошибка: не удалось загрузить приватный ключ RSA для пользователя {user_id} после всех попыток.")
                if key_re_saved_after_decryption:
                    if loaded_private_key:
                         public_key = loaded_private_key.public_key()
                    else:
                         with open(public_key_path, "rb") as f_pub:
                            public_key = serialization.load_pem_public_key(f_pub.read(), backend=default_backend())
                else:
                    with open(public_key_path, "rb") as f_pub:
                        public_key = serialization.load_pem_public_key(f_pub.read(), backend=default_backend())
                
                return loaded_private_key, public_key

            # Генерируем новую пару ключей RSA, если они не существуют
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Сохраняем ключи
            self._save_user_keys(user_id, private_key, public_key)
            
            return private_key, public_key
            
        except Exception as e:
            self.logger.error(f"Ошибка при создании или загрузке RSA ключей для пользователя {user_id}: {e}")
            raise KeyCreationError(f"Ошибка при создании или загрузке RSA ключей для пользователя {user_id}: {e}")

    def _set_key_file_permissions(self, file_path: Path) -> None:
        """ Установка безопасных прав доступа для файла ключа
        Args: file_path: Путь к файлу ключа
        """
        try:
            # Устанавливаем права доступа Windows в зависимости от типа ключа
            if 'private_key' in file_path.name:
                set_windows_private_key_permissions(file_path)
            else:
                set_windows_secure_permissions(file_path)
                
        except Exception as e:
            self.logger.error(f"Ошибка при установке прав доступа: {str(e)}")
            raise KeyCreationError(f"Не удалось установить права доступа для {file_path}")

    def _check_refresh_rate_limit(self, user_id: int) -> bool:
        """Проверка ограничения частоты обновления токенов"""
        current_time = datetime.utcnow()
        if user_id not in self.refresh_attempts:
            self.refresh_attempts[user_id] = []
        
        # Очистка старых попыток
        self.refresh_attempts[user_id] = [
            timestamp for timestamp in self.refresh_attempts[user_id]
            if current_time - timestamp < timedelta(seconds=self.refresh_attempt_window)
        ]
        
        # Проверка количества попыток
        if len(self.refresh_attempts[user_id]) >= self.max_refresh_attempts:
            return False
        
        # Добавление новой попытки
        self.refresh_attempts[user_id].append(current_time)
        return True

    def create_session(self, user_id: int) -> Tuple[str, str]:
        """ Создание новой сессии для пользователя
        Args: user_id: ID пользователя
        Returns: Tuple[str, str]: (токен сессии, refresh токен)
        Raises: SessionCreationError: при ошибке создания сессии
            RateLimitError: при превышении лимита создания сессий
        """
        try:
            if not self._check_session_creation_limit(user_id):
                raise RateLimitError(f"Превышен лимит создания сессий для пользователя {user_id}")
            
            current_time = datetime.utcnow()
            session_id = secrets.token_hex(16)
            
            # Получаем ключи для пользователя
            private_key, public_key = self._init_user_keys(user_id)
            
            # Создаем payload для session token
            session_payload = {
                'user_id': user_id,
                'session_id': session_id,
                'type': 'session',
                'iat': int(current_time.timestamp()),
                'exp': int((current_time + self.session_duration).timestamp())
            }
            
            # Создаем подпись для session token
            signature = private_key.sign(
                json.dumps(session_payload, sort_keys=True).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Добавляем подпись в payload
            session_payload['signature'] = signature.hex()
            
            # Создаем JWT session token
            try:
                session_token = jwt.encode(
                    session_payload,
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ),
                    algorithm='RS256'
                )
            except Exception as e:
                raise SessionCreationError("Ошибка создания JWT токена", e)
            
            # Создаем payload для refresh token
            refresh_payload = {
                'user_id': user_id,
                'session_id': session_id,
                'type': 'refresh',
                'iat': int(current_time.timestamp()),
                'exp': int((current_time + self.refresh_token_duration).timestamp())
            }
            
            # Создаем подпись для refresh token
            refresh_signature = private_key.sign(
                json.dumps(refresh_payload, sort_keys=True).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Добавляем подпись в payload
            refresh_payload['signature'] = refresh_signature.hex()
            
            # Создаем JWT refresh token
            try:
                refresh_token = jwt.encode(
                    refresh_payload,
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ),
                    algorithm='RS256'
                )
            except Exception as e:
                raise SessionCreationError("Ошибка создания refresh JWT токена", e)
            
            # Сохраняем информацию о сессии
            self.active_sessions[session_token] = {
                'user_id': user_id,
                'session_id': session_id,
                'created_at': current_time,
                'expires': current_time + self.session_duration,
                'signature': signature.hex(),
                'public_key': public_key
            }
            
            # Сохраняем информацию о refresh token
            self.refresh_tokens[refresh_token] = {
                'user_id': user_id,
                'session_id': session_id,
                'created_at': current_time,
                'expires': current_time + self.refresh_token_duration,
                'signature': refresh_signature.hex(),
                'public_key': public_key
            }
            
            # Регистрируем активность сессии
            self.auto_logout.update_activity(session_token)
            
            self.logger.info(f"Создана новая сессия для пользователя {user_id}")
            return session_token, refresh_token
            
        except (SessionCreationError, RateLimitError):
            raise
        except Exception as e:
            raise SessionCreationError(f"Непредвиденная ошибка при создании сессии: {str(e)}", e)

    def validate_session(self, token: str) -> Optional[dict]:
        """ Валидация токена сессии
        Args: token: Токен сессии
        Returns: Optional[dict]: Информация о сессии или None если токен невалиден
        Raises: SessionValidationError: при ошибке валидации
            SessionExpiredError: если сессия истекла
        """
        try:
            # Проверяем наличие токена в активных сессиях
            if token not in self.active_sessions:
                # Проверяем, был ли токен удален из-за истечения срока
                current_time = datetime.utcnow()
                try:
                    payload = jwt.decode(token, options={"verify_signature": False})
                    if payload.get('exp') and datetime.fromtimestamp(payload['exp']) < current_time:
                        raise SessionExpiredError("Сессия истекла")
                except jwt.InvalidTokenError:
                    pass
                raise SessionValidationError("Токен не найден в активных сессиях")
            
            session_info = self.active_sessions[token]
            
            # Проверяем срок действия перед любой другой валидацией
            if datetime.utcnow() > session_info['expires']:
                self.invalidate_session(token)
                raise SessionExpiredError("Сессия истекла")
            
            public_key = session_info['public_key']
            
            # Декодируем JWT без верификации для получения payload
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
            except jwt.InvalidTokenError as e:
                raise SessionValidationError("Невалидный формат JWT токена", e)
            
            # Проверяем тип токена
            if payload.get('type') != 'session':
                raise SessionValidationError("Неверный тип токена")
            
            # Извлекаем подпись и создаем копию payload для верификации
            signature_hex = payload.pop('signature', None)
            if not signature_hex:
                raise SessionValidationError("Отсутствует подпись в токене")
            
            try:
                signature = bytes.fromhex(signature_hex)
            except ValueError as e:
                raise SessionValidationError("Невалидный формат подписи", e)
            
            # Верифицируем подпись
            try:
                public_key.verify(
                    signature,
                    json.dumps(payload, sort_keys=True).encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception as e:
                raise SessionValidationError("Неверная подпись токена", e)
            
            return session_info
            
        except (SessionValidationError, SessionExpiredError):
            raise
        except Exception as e:
            raise SessionValidationError(f"Непредвиденная ошибка при валидации сессии: {str(e)}", e)

    def refresh_session_token(self, refresh_token: str) -> Optional[Tuple[str, str]]:
        """ Обновление токена сессии с помощью refresh токена
        Args: refresh_token: Refresh токен
        Returns: Optional[Tuple[str, str]]: (новый токен сессии, новый refresh токен)
        Raises: SessionRefreshError: при ошибке обновления токена
            RateLimitError: при превышении лимита обновлений
            SessionExpiredError: если refresh токен истек
        """
        try:
            if refresh_token not in self.refresh_tokens:
                raise SessionRefreshError("Refresh токен не найден")
            
            refresh_info = self.refresh_tokens[refresh_token]
            public_key = refresh_info['public_key']
            
            try:
                payload = jwt.decode(refresh_token, options={"verify_signature": False})
            except jwt.InvalidTokenError as e:
                raise SessionRefreshError("Невалидный формат refresh токена", e)
            
            if payload.get('type') != 'refresh':
                raise SessionRefreshError("Неверный тип токена")
            
            signature_hex = payload.pop('signature', None)
            if not signature_hex:
                raise SessionRefreshError("Отсутствует подпись в refresh токене")
            
            try:
                signature = bytes.fromhex(signature_hex)
            except ValueError as e:
                raise SessionRefreshError("Невалидный формат подписи", e)
            
            try:
                public_key.verify(
                    signature,
                    json.dumps(payload, sort_keys=True).encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception as e:
                raise SessionRefreshError("Неверная подпись refresh токена", e)
            
            if datetime.utcnow() > refresh_info['expires']:
                del self.refresh_tokens[refresh_token]
                raise SessionExpiredError("Refresh токен истек")
            
            user_id = refresh_info['user_id']
            if not self._check_refresh_rate_limit(user_id):
                raise RateLimitError(f"Превышен лимит обновлений для пользователя {user_id}")
            
            try:
                new_session_token, new_refresh_token = self.create_session(user_id)
            except Exception as e:
                raise SessionRefreshError("Ошибка создания новой сессии", e)
            
            del self.refresh_tokens[refresh_token]
            
            self.logger.info(f"Успешное обновление сессии для пользователя {user_id}")
            return new_session_token, new_refresh_token
            
        except (SessionRefreshError, RateLimitError, SessionExpiredError):
            raise
        except Exception as e:
            raise SessionRefreshError(f"Непредвиденная ошибка при обновлении сессии: {str(e)}", e)

    def invalidate_session(self, token: str) -> bool:
        """ Аннулирование сессии
        Returns: bool: True если сессия успешно аннулирована
        """
        try:
            if token in self.active_sessions:
                user_id = self.active_sessions[token]['user_id']
                del self.active_sessions[token]
                self.auto_logout.remove_session(token)
                self.logger.info(f"Сессия пользователя {user_id} успешно аннулирована")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Ошибка при аннулировании сессии: {str(e)}")
            return False

    def is_valid_session(self, token: str) -> bool:
        """ Проверка валидности сессии с учетом времени неактивности
        Args: token: Токен сессии
        Returns: bool: True если сессия валидна
        """
        if token not in self.active_sessions:
            return False
        # Проверяем время жизни сессии
        session_data = self.active_sessions[token]
        if datetime.utcnow() > session_data['expires']:
            self.invalidate_session(token)
            return False
        # Проверяем время неактивности
        if self.auto_logout.is_session_inactive(token):
            self.invalidate_session(token)
            return False
        # Обновляем время последней активности
        self.auto_logout.update_activity(token)
        return True
