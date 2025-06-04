import tkinter as tk
from tkinter import ttk, font, messagebox
import logging
from password_manager.config import Config
from password_manager.gui.menu_window import MenuP
from password_manager.gui.secret_window import Secret
from password_manager.database.database_manager import DatabaseManager
from password_manager.security.session import SessionManager
from password_manager.security.auto_logout import AutoLogout
from password_manager.encryption import EncryptionService
from password_manager.security.password_security import PasswordSecurity
from pathlib import Path

logger = logging.getLogger(__name__)


class MasterPasswordDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.controller = parent  # Установка контроллера
        self.title("Set Master Password")
        self.geometry("400x300")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        # Центрирование диалога
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
        
        self.result = None
        self._create_widgets()

        # Проверяем, есть ли пользователи в базе данных
        db = DatabaseManager()
        user_ids = db.get_user_ids()

        # Если пользователей нет, показываем окно регистрации
        if not user_ids:
            self.after(100, lambda: self.controller.show_frame("Register"))
        else:
            self.after(100, lambda: self.controller.show_frame("MenuP"))

    def _create_widgets(self):
        # Инструкции
        instructions = tk.Label(self, text="Please create a master password.\n\n"
                              "Requirements:\n"
                              "• At least 12 characters long\n"
                              "• Contains uppercase letters\n"
                              "• Contains lowercase letters\n"
                              "• Contains numbers\n"
                              "• Contains special characters (!@#$%^&*)",
                              justify=tk.LEFT)
        instructions.pack(pady=10, padx=20)
        
        # Ввод пароля
        pw_frame = ttk.LabelFrame(self, text="Master Password")
        pw_frame.pack(fill="x", padx=20, pady=10)
        
        self.password = ttk.Entry(pw_frame, show="*")
        self.password.pack(fill="x", padx=10, pady=5)
        
        # Подтверждение пароля
        confirm_frame = ttk.LabelFrame(self, text="Confirm Password")
        confirm_frame.pack(fill="x", padx=20, pady=10)
        
        self.config = Config()
        self.confirm = ttk.Entry(confirm_frame, show="*")
        self.confirm.pack(fill="x", padx=10, pady=5)
        
        # Кнопки
        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Button(button_frame, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=5)
        # Привязка клавиши Enter
        self.bind("<Return>", lambda e: self._on_ok())
        self.bind("<Escape>", lambda e: self._on_cancel())
        self.password.focus()  # Фокус на поле ввода пароля

    def _validate_password(self, password: str) -> tuple[bool, str]:
        """Проверка надежности пароля с использованием PasswordSecurity."""
        return PasswordSecurity.validate_password(password)
    
    def _on_ok(self):
        password = self.password.get()
        confirm = self.confirm.get()
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        valid, message = self._validate_password(password)
        if not valid:
            messagebox.showerror("Error", message)
            return
        
        self.result = password
        self.destroy()
    
    def _on_cancel(self):
        self.result = None
        self.destroy()


class MainWindow(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Password Manager")
        self.geometry("700x200+100+70")
        self.resizable(True, True)
        self.title_font = font.Font(family='Helvetica', size=18, weight="bold", slant="italic")
        
        # Initialize configuration
        from password_manager.config import Config
        self.config = Config()
        
        # Check database password and initialize if needed
        if not self._ensure_database_initialization():
            self.quit()
            return
            
        # Initialize database
        try:
            self.db_manager = DatabaseManager()
            self.db_manager.initialize_database()
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            messagebox.showerror("Error", f"Failed to initialize database: {str(e)}")
            self.quit()
            return
        
        # Default to admin user (id=1) for initial setup
        self.current_user_id = 1
        
        # Get base directory for encryption
        self.base_dir = Path(__file__).parent.parent / "secure_data" / "users" / str(self.current_user_id)
        
        # Initialize security features
        self.encryption_service = EncryptionService(str(self.base_dir))
        self.session_manager = SessionManager()
        self.auto_logout = AutoLogout(self, timeout_minutes=5, callback=self.handle_auto_logout)
        self.current_session = None
        self.refresh_token = None
        self.session_refresh_timer = None
        
        # Create container for frames
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        # Initialize frames
        self.frames = {}
        self._init_frames(container)
        self.show_frame("MenuP")

    def _ensure_database_initialization(self) -> bool:
        """
        Ensures the database passphrase is set in Config.
        This should have been handled by Application.initialize() before MainWindow is created.
        Returns:
            bool: True if passphrase is set, False otherwise (unexpected state).
        """
        try:
            # The master password (passphrase) should have been set by Application.initialize()
            # via _check_database_password before MainWindow is even created.
            if self.config.get_master_password() is not None:
                logger.info("Database passphrase confirmed in Config for MainWindow.")
                return True
            else:
                # This case should ideally not be reached if __main__.py logic is correct.
                logger.error("CRITICAL: MainWindow created but no master password in Config!")
                messagebox.showerror(
                    "Critical Error", 
                    "Database passphrase was not set during application startup. Cannot continue."
                )
                return False
            
        except Exception as e:
            # Catch any other unexpected exceptions during the check.
            logger.error(f"Unexpected error in _ensure_database_initialization: {e}", exc_info=True)
            messagebox.showerror("Critical Error", f"An unexpected error occurred checking database readiness: {str(e)}")
            return False

    def set_user_id(self, user_id: int):
        """Обновление ID пользователя и реинициализация функций безопасности"""
        self.current_user_id = user_id
        self.base_dir = Path(__file__).parent.parent / "secure_data" / "users" / str(user_id)
        self.encryption_service = EncryptionService(str(self.base_dir))
    
    def _init_frames(self, container):
        for F in (Secret, MenuP):
            page_name = F.__name__
            if page_name == "Secret":
                frame = F(parent=container, controller=self, user_id=None)
            else:
                frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
    
    def start_session_refresh_timer(self):
        """Запуск таймера для обновления сессии"""
        if self.session_refresh_timer:
            self.after_cancel(self.session_refresh_timer)
        
        # Обновляем сессию каждые 4 минуты (при длительности сессии 5 минут)
        self.session_refresh_timer = self.after(240000, self.refresh_current_session)

    def refresh_current_session(self):
        """Обновление текущей сессии"""
        try:
            if self.current_session and self.refresh_token:
                new_access_token, new_refresh_token = self.session_manager.refresh_session_token(self.refresh_token)
                if new_access_token and new_refresh_token:
                    self.current_session = new_access_token
                    self.refresh_token = new_refresh_token
                    self.start_session_refresh_timer()
                else:
                    messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
                    self.show_frame("MenuP")
        except Exception as e:
            logger.error(f"Error refreshing session: {str(e)}")
            self.show_frame("MenuP")

    def show_frame(self, page_name, user_id=None):
        if page_name == "MenuP":
            self.geometry("700x200")
            # Очистка сессии при возврате в меню
            if self.current_session:
                self.session_manager.invalidate_session(self.current_session)
            self.current_session = None
            self.refresh_token = None
            if self.session_refresh_timer:
                self.after_cancel(self.session_refresh_timer)
            self.auto_logout.stop()
        else:
            self.geometry("800x670")
            if user_id:
                # Создание новой сессии при входе
                self.current_session, self.refresh_token = self.session_manager.create_session(user_id)
                if not self.current_session or not self.refresh_token:
                    messagebox.showerror("Error", "Failed to create session")
                    self.show_frame("MenuP")
                    return
                # Запуск таймеров
                self.auto_logout.reset_timer()
                self.start_session_refresh_timer()
        
        frame = self.frames[page_name]
        if user_id is not None:
            frame.user_id = user_id
        frame.tkraise()
        frame.event_generate("<<ShowFrame>>")
        
        if page_name == "Secret":
            frame.refresh_table()

    def validate_session(self) -> bool:
        """Валидация сессии"""
        if not self.current_session:
            return False
        
        try:
            if self.session_manager.is_valid_session(self.current_session):
                return True
            
            # Пробуем обновить сессию через refresh token
            if self.refresh_token:
                new_access_token, new_refresh_token = self.session_manager.refresh_session_token(self.refresh_token)
                if new_access_token and new_refresh_token:
                    self.current_session = new_access_token
                    self.refresh_token = new_refresh_token
                    self.start_session_refresh_timer()
                    return True
            
            messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
            self.show_frame("MenuP")
            return False
        except Exception as e:
            messagebox.showerror("Error", f"Session validation error: {str(e)}")
            self.show_frame("MenuP")
            return False

    def handle_auto_logout(self):
        if self.current_session:
            self.session_manager.invalidate_session(self.current_session)
            self.current_session = None
            self.refresh_token = None
            if self.session_refresh_timer:
                self.after_cancel(self.session_refresh_timer)
            messagebox.showinfo("Auto Logout", "You have been logged out due to inactivity")
            self.show_frame("MenuP")

    def destroy(self):
        # Корректное завершение работы SessionManager
        if hasattr(self, 'session_manager') and self.session_manager:
            logger.info("Shutting down SessionManager from MainWindow...")
            self.session_manager.shutdown()
        
        # Завершение работы таймера автовыхода, если он существует
        if hasattr(self, 'auto_logout') and self.auto_logout:
            logger.info("Stopping AutoLogout timer from MainWindow...")
            self.auto_logout.stop() # Убедимся, что таймер auto_logout остановлен

        # Cancel the session refresh timer
        if hasattr(self, 'session_refresh_timer') and self.session_refresh_timer:
            logger.info("Stopping session refresh timer from MainWindow...")
            try:
                self.after_cancel(self.session_refresh_timer)
                self.session_refresh_timer = None
            except Exception as e:
                logger.warning(f"Error cancelling session_refresh_timer: {e}")

        # Explicitly quit the mainloop for this Tk instance and then destroy
        logger.debug("MainWindow.destroy(): Attempting to quit and then call super().destroy()")
        try:
            self.quit()  # Ensure mainloop terminates
        except Exception as e:
            logger.error(f"Error during MainWindow.quit(): {e}")
        
        # Вызов оригинального метода destroy
        super().destroy()
