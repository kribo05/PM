import unittest
import tempfile
import json
import time
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

class TestBasicSecurity(unittest.TestCase):
    def setUp(self):
        """Подготовка тестового окружения"""
        self.test_dir = Path(tempfile.mkdtemp(prefix="pm_test_basic_security_"))
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

    def tearDown(self):
        """Очистка после тестов"""
        try:
            if self.test_dir.exists():
                import shutil
                shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Warning: Failed to cleanup test directory: {e}")

    def test_data_tampering(self):
        """
        Тест проверяет обнаружение подмены зашифрованных данных
        """
        # Исходные данные
        original_data = {
            "service": "TestService",
            "username": "test@example.com",
            "password": "SecretPassword123!"
        }
        # Шифруем данные
        encrypted = self.fernet.encrypt(json.dumps(original_data).encode())
        # Пытаемся подменить зашифрованные данные
        tampered = bytearray(encrypted)
        # Модифицируем несколько байтов в середине
        midpoint = len(tampered) // 2
        tampered[midpoint:midpoint+5] = b'XXXXX' # Замена 5 байт в середине заш. сообщения
        # Проверяем что подмененные данные не могут быть расшифрованы
        with self.assertRaises(InvalidToken):
            self.fernet.decrypt(bytes(tampered))
        # Проверяем что оригинальные данные все еще можно расшифровать
        decrypted = json.loads(self.fernet.decrypt(encrypted).decode())
        self.assertEqual(original_data, decrypted)

    def test_data_integrity(self):
        """
        Тест проверяет сохранение целостности данных при шифровании
        """
        test_cases = [
            "Simple password",
            "Password with спецсимволы",
            "Password with 🔑 emoji",
            "A" * 1000,  # Длинный пароль
            "!@#$%^&*()_+-=[]{}|;:,.<>?",  # Специальные символы
            "",  # Пустая строка
            " " * 100,  # Много пробелов
            "1234567890" * 10,  # Повторяющиеся цифры
        ]
        
        for test_data in test_cases:
            # Шифруем
            encrypted = self.fernet.encrypt(test_data.encode())
            # Расшифровываем
            decrypted = self.fernet.decrypt(encrypted).decode()
            # Проверяем что данные совпадают
            self.assertEqual(
                test_data, 
                decrypted,
                f"Ошибка целостности данных для: {test_data[:50]}..."
            )

    def test_key_separation(self):
        """
        Тест проверяет что данные, зашифрованные одним ключом,
        нельзя расшифровать другим ключом
        """
        # Создаем второй ключ
        another_key = Fernet.generate_key()
        another_fernet = Fernet(another_key)
        
        # Данные для теста
        test_data = "Secret message"
        
        # Шифруем первым ключом
        encrypted = self.fernet.encrypt(test_data.encode())
        
        # Пытаемся расшифровать вторым ключом
        with self.assertRaises(InvalidToken):
            another_fernet.decrypt(encrypted)
        
        # Проверяем что оригинальным ключом все еще можно расшифровать
        decrypted = self.fernet.decrypt(encrypted).decode()
        self.assertEqual(test_data, decrypted)

    def test_timestamp_validation(self):
        """
        Тест проверяет что токены имеют ограничение по времени
        """
        # Создаем Fernet с очень коротким TTL
        short_ttl_fernet = Fernet(Fernet.generate_key())
        
        # Шифруем данные
        test_data = "Time sensitive data"
        encrypted = short_ttl_fernet.encrypt(test_data.encode())
        
        # Проверяем что сразу можно расшифровать
        decrypted = short_ttl_fernet.decrypt(encrypted, ttl=100).decode()
        self.assertEqual(test_data, decrypted)
        
        # Ждем 2 секунды
        time.sleep(2)
        
        # Пытаемся расшифровать с TTL в 1 секунду (должно вызвать ошибку)
        with self.assertRaises(InvalidToken):
            short_ttl_fernet.decrypt(encrypted, ttl=1)

if __name__ == '__main__':
    unittest.main(verbosity=2) 