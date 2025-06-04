import time
import unittest
from password_manager.security.session import (
    SessionManager,
    SessionExpiredError,
    RateLimitError,
    SessionRefreshError
)


class TestSessionSecurity(unittest.TestCase):
    def setUp(self):
        """
        Инициализация теста с коротким временем жизни сессии
        для тестирования механизма истечения
        """
        # Устанавливаем время жизни сессии в 1 минуту и refresh token в 2 минуты
        self.session_manager = SessionManager(
            session_duration=1,  # 1 минута
            refresh_token_duration=2  # 2 минуты
        )
        self.test_user_id = 12345

    def tearDown(self):
        """Очистка после тестов"""
        # Корректно завершаем работу менеджера сессий
        if self.session_manager:
            self.session_manager.shutdown()
        
        # Принудительно очищаем словари для чистоты тестов
        # Это безопасно делать после shutdown()
        if hasattr(self.session_manager, 'active_sessions'):
            self.session_manager.active_sessions.clear()
        if hasattr(self.session_manager, 'refresh_tokens'):
            self.session_manager.refresh_tokens.clear()
        if hasattr(self.session_manager, 'refresh_attempts'):
            self.session_manager.refresh_attempts.clear()
        if hasattr(self.session_manager, 'session_creation_attempts'):
            self.session_manager.session_creation_attempts.clear()

    def test_session_creation_and_validation(self):
        """Тест создания и валидации сессии"""
        # Создаем сессию
        session_token, refresh_token = self.session_manager.create_session(self.test_user_id)
        
        # Проверяем валидность сессии
        self.assertTrue(self.session_manager.is_valid_session(session_token))
        
        # Проверяем данные сессии
        session_info = self.session_manager.validate_session(session_token)
        self.assertIsNotNone(session_info)
        self.assertEqual(session_info['user_id'], self.test_user_id)

    def test_session_expiration(self):
        """Тест истечения сессии"""
        # Используем отдельный экземпляр SessionManager для этого теста, чтобы не влиять на self.session_manager
        sm = SessionManager(session_duration=1/12)  # 5 секунд
        session_token, _ = sm.create_session(self.test_user_id)
        
        # Проверяем, что сессия изначально валидна
        self.assertTrue(sm.is_valid_session(session_token))
        
        # Ждем истечения сессии
        time.sleep(6)  # Ждем 6 секунд
        
        # Проверяем, что сессия истекла
        self.assertFalse(sm.is_valid_session(session_token))
        
        # Проверяем, что validate_session выбрасывает исключение
        with self.assertRaises(SessionExpiredError):
            sm.validate_session(session_token)
        sm.shutdown()

    def test_session_token_reuse(self):
        """Тест на повторное использование устаревшего токена"""
        # Создаем сессию с коротким временем жизни
        sm = SessionManager(session_duration=1/60)  # 1 секунда
        session_token, _ = sm.create_session(self.test_user_id) #время истечения или статус не учитывается
        # Сохраняем токен
        stored_token = session_token
        # Ждем истечения сессии
        time.sleep(2)
        # Пытаемся использовать устаревший токен
        self.assertFalse(sm.is_valid_session(stored_token))
        with self.assertRaises(SessionExpiredError):
            sm.validate_session(stored_token)
        sm.shutdown()

    def test_multiple_sessions(self):
        """Тест работы с несколькими сессиями"""
        # Создаем две сессии
        session1, refresh1 = self.session_manager.create_session(self.test_user_id)
        session2, refresh2 = self.session_manager.create_session(self.test_user_id + 1) # Разные user_id для наглядности
        
        # Проверяем, что обе сессии валидны
        self.assertTrue(self.session_manager.is_valid_session(session1))
        self.assertTrue(self.session_manager.is_valid_session(session2))
        
        # Инвалидируем первую сессию
        self.session_manager.invalidate_session(session1)
        
        # Проверяем состояние сессий
        self.assertFalse(self.session_manager.is_valid_session(session1))
        self.assertTrue(self.session_manager.is_valid_session(session2))

    def test_refresh_token(self):
        """Тест обновления сессии"""
        # Создаем сессию
        session_token, refresh_token = self.session_manager.create_session(self.test_user_id)
        
        result = self.session_manager.refresh_session_token(refresh_token)
        self.assertIsNotNone(result, "refresh_session_token should return a new pair of tokens")
        new_session_token, new_refresh_token = result
        
        # Проверяем новую сессию
        self.assertTrue(self.session_manager.is_valid_session(new_session_token))
        self.assertNotEqual(session_token, new_session_token)
        self.assertNotEqual(refresh_token, new_refresh_token) # Новый refresh токен также должен быть другим
        
        # Старый refresh_token должен быть удален и стать невалидным
        with self.assertRaises(SessionRefreshError): # Ожидаем ошибку, что токен не найден или невалиден
            self.session_manager.refresh_session_token(refresh_token)

    def test_refresh_rate_limiting(self):
        """Тест ограничения частоты обновления сессий"""
        session_token, current_refresh_token = self.session_manager.create_session(self.test_user_id)
        
        # Выполняем максимальное количество обновлений
        for i in range(self.session_manager.max_refresh_attempts):
            result = self.session_manager.refresh_session_token(current_refresh_token)
            self.assertIsNotNone(result, f"Token refresh attempt #{i+1} should succeed.")
            _, current_refresh_token = result # Use the new refresh token for the next attempt
            # time.sleep(0.01) # Small delay might be needed if window is very short, but usually not.
        
        # Следующая попытка должна вызвать ошибку
        with self.assertRaises(RateLimitError):
            self.session_manager.refresh_session_token(current_refresh_token)


if __name__ == '__main__':
    unittest.main()
