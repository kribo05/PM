from datetime import datetime, timedelta
from typing import Callable, Dict
import tkinter as tk


class AutoLogoutManager:
    """
    Менеджер для отслеживания активности пользователя в системе.
    Используется для определения неактивности пользователя и автоматического выхода.
    """
    def __init__(self, timeout_seconds: int = 300):
        """
        Инициализация менеджера автоматического выхода
        Args:
            timeout_seconds: Время неактивности в секундах до автоматического выхода
        """
        self._timeout = timeout_seconds
        self._last_activity: Dict[str, datetime] = {}
    
    def update_activity(self, session_token: str) -> None:
        """
        Обновление времени последней активности для сессии
        Args:
            session_token: Токен сессии
        """
        self._last_activity[session_token] = datetime.now()
    
    def get_inactivity_time(self, session_token: str) -> timedelta:
        """
        Получение времени неактивности для сессии
        Args:
            session_token: Токен сессии
        Returns:
            timedelta: Время неактивности
        """
        if session_token not in self._last_activity:
            return timedelta.max
        
        return datetime.now() - self._last_activity[session_token]
    
    def is_session_inactive(self, session_token: str) -> bool:
        """
        Проверка, превышено ли время неактивности для сессии
        Args:
            session_token: Токен сессии
        Returns:
            bool: True если сессия неактивна дольше timeout
        """
        if session_token not in self._last_activity:
            return True
        
        inactivity_time = self.get_inactivity_time(session_token)
        return inactivity_time.total_seconds() > self._timeout
    
    def remove_session(self, session_token: str) -> None:
        """
        Удаление информации об активности сессии
        Args:
            session_token: Токен сессии
        """
        self._last_activity.pop(session_token, None)


class AutoLogout:
    def __init__(self, root: tk.Tk, timeout_minutes: int = 5, callback: Callable = None):
        self.root = root
        self.timeout = timeout_minutes * 60 * 1000  # Преобразование в миллисекунды
        self.callback = callback
        self.timer = None
        self.last_activity = datetime.now()
        
        # Привязка событий для отслеживания активности пользователя
        self._bind_events()
        
        # Запуск таймера
        self.reset_timer()
    
    def _bind_events(self):
        self.root.bind_all('<Key>', self._activity)
        self.root.bind_all('<Button-1>', self._activity)
        self.root.bind_all('<Button-2>', self._activity)
        self.root.bind_all('<Button-3>', self._activity)
        self.root.bind_all('<Motion>', self._activity)
        self.root.bind_all('<MouseWheel>', self._activity)
    
    def _activity(self, event=None):
        self.last_activity = datetime.now()
        self.reset_timer()
    
    def reset_timer(self):
        if self.timer:
            self.root.after_cancel(self.timer)
        self.timer = self.root.after(self.timeout, self._logout)
    
    def _logout(self):
        if self.callback:
            self.callback()
    
    def stop(self):
        if self.timer:
            self.root.after_cancel(self.timer)
            self.timer = None
