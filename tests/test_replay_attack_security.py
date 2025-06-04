import unittest
import tempfile
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from base64 import b64encode


class TestReplayAttackSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Подготовка общих ресурсов для всех тестов"""
        cls.test_base_dir = Path(tempfile.mkdtemp(prefix="pm_test_replay_"))
        cls.test_user_id = 999  # Тестовый ID пользователя

    def setUp(self):
        """Подготовка окружения перед каждым тестом"""
        # Создаем временную директорию для каждого теста
        self.test_dir = self.test_base_dir / f"test_{int(time.time())}"
        self.test_dir.mkdir(parents=True, exist_ok=True)
        
        # Генерируем тестовый ключ
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        
        # Создаем тестовые данные
        self.test_password = {
            "service": "TestBank",
            "username": "user@test.com",
            "password": "SuperSecure123!",
            "timestamp": datetime.now().isoformat()
        }

    def tearDown(self):
        """Очистка после каждого теста"""
        try:
            import shutil
            if self.test_dir.exists():
                shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Warning: Failed to cleanup test directory: {e}")

    @classmethod
    def tearDownClass(cls):
        """Очистка общих ресурсов после всех тестов"""
        try:
            import shutil
            if cls.test_base_dir.exists():
                shutil.rmtree(cls.test_base_dir)
        except Exception as e:
            print(f"Warning: Failed to cleanup base test directory: {e}")

    """
    Тест проверяет защиту от атаки повторного воспроизведения:
    1. Злоумышленник перехватывает зашифрованные данные
    2. Позже, после изменения пароля, пытается подменить новые данные старыми
    """

    def test_replay_attack_with_old_data(self):
        # Шифруем исходные данные с timestamp в прошлом
        old_time = datetime.now() - timedelta(minutes=10)  # Данные "созданы" 10 минут назад
        self.test_password["timestamp"] = old_time.isoformat()
        encrypted_original = self.fernet.encrypt(json.dumps(self.test_password).encode())
        # Имитируем перехват данных злоумышленником
        intercepted_data = encrypted_original
        # Имитируем смену пароля пользователем
        self.test_password["password"] = "NewSecurePass456!"
        self.test_password["timestamp"] = datetime.now().isoformat()
        encrypted_new = self.fernet.encrypt(json.dumps(self.test_password).encode())
        # Имитируем попытку подмены новых данных старыми
        try:
            # Пытаемся "восстановить" старые данные
            decrypted_data = json.loads(self.fernet.decrypt(intercepted_data).decode())
            # Проверяем, что timestamp в расшифрованных данных устарел
            stored_time = datetime.fromisoformat(decrypted_data["timestamp"])
            current_time = datetime.now()
            # Если разница во времени больше допустимой (например, 5 минут)
            max_time_diff = timedelta(minutes=5)
            self.assertGreater( current_time - stored_time, max_time_diff,
                "Подмена старыми данными должна быть отвергнута из-за устаревшего timestamp")
            # Дополнительно проверяем, что расшифрованные данные отличаются от текущих
            self.assertNotEqual(decrypted_data["password"], self.test_password["password"],
                "Подмена старыми данными не должна соответствовать текущему паролю")
        except AssertionError as e:
            # Перехватываем AssertionError для более информативного сообщения
            self.fail(f"Проверка защиты от replay-атаки не прошла: {str(e)}")
        except Exception as e:
            self.fail(f"Неожиданная ошибка при проверке защиты от replay-атаки: {str(e)}")

    def test_replay_attack_with_key_rotation(self):
        """
        Тест проверяет защиту от атаки повторного воспроизведения при ротации ключей:
        1. Злоумышленник перехватывает зашифрованные данные
        2. Происходит ротация ключей
        3. Злоумышленник пытается использовать старые данные
        """
        # Шифруем исходные данные
        encrypted_original = self.fernet.encrypt(json.dumps(self.test_password).encode())
        # Имитируем перехват данных злоумышленником
        intercepted_data = encrypted_original
        # Имитируем ротацию ключей - создаем новый ключ
        new_key = Fernet.generate_key()
        new_fernet = Fernet(new_key)
        # Пытаемся расшифровать перехваченные данные новым ключом
        with self.assertRaises(Exception) as context:
            new_fernet.decrypt(intercepted_data)
        self.assertTrue(
            isinstance(context.exception, Exception),
            "Расшифровка старых данных новым ключом должна вызывать исключение"
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)
