import os
import json
import logging
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from password_manager.encryption.key_factory_class import KeyFactory


class CryptoManager:
    """Управляет операциями шифрования/дешифрования"""
    def __init__(self, base_dir=None, key_factory=None):
        """
        Инициализирует менеджер криптографии
        Args: base_dir: Базовая директория проекта. Если None, определяется автоматически.
            key_factory: Фабрика ключей. Если None, создается новый экземпляр.
        """
        if base_dir is None:
            self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        else:
            self.base_dir = base_dir
            
        self.key_factory = key_factory or KeyFactory()
        self.logger = logging.getLogger(__name__)

    def encrypt_password(self, password, user_id, retry_count=0):
        """
        Шифрует пароль для указанного пользователя
        Args:password: Пароль для шифрования
            user_id: ID пользователя
            retry_count: Счетчик попыток (для предотвращения бесконечной рекурсии)
        Returns: str: Зашифрованный пароль в формате JSON
        """
        if not password:
            raise ValueError("Пароль не может быть пустым")
            
        if retry_count >= 3:
            raise ValueError("Превышено максимальное количество попыток шифрования")
            
        try:
            # Проверяем, что ключ AES существует
            self._ensure_aes_key_exists(user_id)
            # Получаем AES менеджер
            _, aes_key_manager = self.key_factory.get_key_managers(self.base_dir, user_id)
            # Получаем текущий ключ AES
            key = aes_key_manager.get_current_key()
            # Генерируем одноразовое число и заголовок
            nonce = get_random_bytes(16)
            header = b"password_manager_v1"
            # Создаем SIV шифр
            cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
            # Обновление заголовка и шифруем пароль
            cipher.update(header)
            ciphertext, tag = cipher.encrypt_and_digest(password.encode())
            # Сериализация зашифрованных данных
            return self._serialize_encrypted_data(nonce, header, ciphertext, tag)
            
        except Exception as e:
            self.logger.error(f"Ошибка шифрования: {e}")
            # В случае ошибки, пробуем сбросить кэш и повторить
            try:
                self.key_factory.clear_key_managers_cache(user_id)
                self._ensure_aes_key_exists(user_id)
                return self.encrypt_password(password, user_id, retry_count + 1)
            except Exception as retry_error:
                self.logger.error(f"Повторная попытка шифрования не удалась: {retry_error}")
                raise
    
    def decrypt_password(self, encrypted_password, user_id):
        """
        Расшифровывает пароль для указанного пользователя
        Args:encrypted_password: Зашифрованный пароль в формате JSON
            user_id: ID пользователя
        Returns: str: Расшифрованный пароль
        """
        try:
            # Проверяем, что ключ AES существует
            self._ensure_aes_key_exists(user_id)
            # Получаем AES менеджер
            _, aes_key_manager = self.key_factory.get_key_managers(self.base_dir, user_id)
            # Получаем текущий ключ
            key = aes_key_manager.get_current_key()
            # Десериализуем зашифрованные данные
            data = self._deserialize_encrypted_data(encrypted_password)
            # Создаем SIV шифр
            cipher = AES.new(key, AES.MODE_SIV, nonce=data['nonce'])
            # Обновляем заголовок и расшифровываем
            cipher.update(data['header'])
            plaintext = cipher.decrypt_and_verify(data['ciphertext'], data['tag'])
            return plaintext.decode()
            
        except Exception as e:
            self.logger.error(f"Ошибка расшифровки: {e}")
            return self._try_decrypt_with_previous_keys(encrypted_password, user_id)
    
    def _try_decrypt_with_previous_keys(self, encrypted_password, user_id):
        """Пытается расшифровать пароль с использованием предыдущих ключей"""
        try:
            # Проверяем, что ключ AES существует
            self._ensure_aes_key_exists(user_id)
            # Получаем AES менеджер
            _, aes_key_manager = self.key_factory.get_key_managers(self.base_dir, user_id)
            for prev_key_data in aes_key_manager.get_previous_keys():
                try:
                    prev_key = aes_key_manager.decode_key(prev_key_data["key"])
                    data = self._deserialize_encrypted_data(encrypted_password)
                    
                    cipher = AES.new(prev_key, AES.MODE_SIV, nonce=data['nonce'])
                    cipher.update(data['header'])
                    plaintext = cipher.decrypt_and_verify(data['ciphertext'], data['tag'])

                    # Если успешно, перешифровываем с текущим ключом
                    self.logger.info("Успешно расшифровано с использованием предыдущего ключа. Перешифрование с текущим ключом.")
                    new_encrypted = self.encrypt_password(plaintext.decode(), user_id)
                    return plaintext.decode(), new_encrypted
                except Exception:
                    continue
                    
            # Если все предыдущие ключи не помогли, пробуем сбросить кэш
            self.key_factory.clear_key_managers_cache(user_id)
            self._ensure_aes_key_exists(user_id)
            
            # Получаем AES менеджер заново
            _, aes_key_manager = self.key_factory.get_key_managers(self.base_dir, user_id)
            key = aes_key_manager.get_current_key()
            
            data = self._deserialize_encrypted_data(encrypted_password)
            cipher = AES.new(key, AES.MODE_SIV, nonce=data['nonce'])
            cipher.update(data['header'])
            plaintext = cipher.decrypt_and_verify(data['ciphertext'], data['tag'])
            
            return plaintext.decode()
        except Exception:
            raise ValueError("Не удалось расшифровать пароль ни одним из доступных ключей")
    
    def _ensure_aes_key_exists(self, user_id):
        """Убедиться, что ключ AES существует для пользователя"""
        try:
            # Сначала очищаем кэш для указанного пользователя
            self.key_factory.clear_key_managers_cache(user_id)
            # Проверяем и получаем AES менеджер
            _, aes_manager = self.key_factory.get_key_managers(self.base_dir, user_id)
            # Проверяем наличие файла ключей
            if not aes_manager.keys_file.exists():
                # Если файл не существует, принудительно создаем ключи
                self.logger.warning(f"AES ключ не найден для пользователя {user_id}, создаем принудительно")
                fernet_created, aes_created = self.key_factory.force_create_keys(self.base_dir, user_id)
                if not aes_created:
                    # Если принудительное создание не помогло, пробуем создать напрямую
                    self.logger.warning(f"Не удалось создать AES ключ через force_create_keys, пробуем прямой метод")
                    aes_manager._create_new_keys()  # Это создаст keys_data
                    # Проверяем еще раз
                    if not aes_manager.keys_file.exists():
                        self.logger.error(f"Не удалось создать AES ключ для пользователя {user_id} даже прямым методом")
                        raise ValueError(f"Не удалось создать AES ключ для пользователя {user_id}")
                    else:
                        self.logger.info(f"AES ключ успешно создан прямым методом для пользователя {user_id}")
                else:
                    self.logger.info(f"AES ключ успешно создан для пользователя {user_id}")
            else:
                self.logger.debug(f"AES ключ существует для пользователя {user_id}")

            # После того как ключ точно существует (загружен или создан), проверяем необходимость ротации
            # aes_manager.keys_data должен быть инициализирован после _load_or_create_keys или _create_new_keys
            if hasattr(aes_manager, 'keys_data') and aes_manager.keys_data and aes_manager.should_rotate_key():
                self.logger.info(f"AES key for user {user_id} needs rotation. Rotating...")
                if aes_manager.rotate_key():
                    self.logger.info(f"AES key for user {user_id} rotated successfully.")
                else:
                    self.logger.error(f"Failed to rotate AES key for user {user_id}.")

        except Exception as e:
            self.logger.error(f"Ошибка при проверке/создании ключа AES: {e}")
            raise
    
    def _serialize_encrypted_data(self, nonce, header, ciphertext, tag):
        """Сериализация зашифрованных данных в формат JSON"""
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        json_v = [base64.b64encode(x).decode('utf-8') for x in (nonce, header, ciphertext, tag)]
        return json.dumps(dict(zip(json_k, json_v)))

    def _deserialize_encrypted_data(self, encrypted_data):
        """Десериализация зашифрованных данных из формата JSON"""
        try:
            data = json.loads(encrypted_data)
            json_k = ['nonce', 'header', 'ciphertext', 'tag']
            return {k: base64.b64decode(data[k]) for k in json_k}
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.logger.error(f"Не удалось десериализовать зашифрованные данные: {e}")
            raise ValueError("Неверный формат зашифрованных данных")
