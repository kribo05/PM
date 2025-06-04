from tkinter import messagebox, ttk
import tkinter as tk
from password_manager.utils.logging_config import setup_logging

logger = setup_logging()


class LoginWindow(tk.Toplevel):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.pw_entry = None
        self.user_entry = None
        self.controller = controller
        self.title("Login")
        self.geometry("350x220")
        self.resizable(False, False)
        # Создание и размещение виджетов
        self.create_widgets()
        # Центрирование окна
        self.center_window()
        # Делаем окно модальным
        self.transient(parent)
        self.grab_set()
        # Ожидание закрытия окна
        parent.wait_window(self)
    
    def create_widgets(self):
        # Username
        ttk.Label(self, text="Username:").pack(pady=5)
        self.user_entry = ttk.Entry(self)
        self.user_entry.pack(pady=5)
        
        # Password
        ttk.Label(self, text="Password:").pack(pady=5)
        self.pw_entry = ttk.Entry(self, show="*")
        self.pw_entry.pack(pady=5)
        
        # Login button
        ttk.Button(self, text="Login", command=self._check_pw).pack(pady=10)
        
        # Привязка клавиши Enter для входа
        self.bind('<Return>', lambda e: self._check_pw())
    
    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
    
    def _check_pw(self):
        username = self.user_entry.get().strip()
        password = self.pw_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty!")
            return

        try:
            # Проверка учетных данных пользователя
            user_id = self.controller.db_manager.verify_user(username, password)
            
            if user_id is not None:
                # Создание новой сессии с refresh token
                access_token, refresh_token = self.controller.session_manager.create_session(user_id)
                if access_token and refresh_token:
                    self.controller.current_session = access_token
                    self.controller.refresh_token = refresh_token
                    self.controller.current_user_id = user_id
                    self.destroy()
                    self.controller.show_frame("Secret", user_id)
                else:
                    messagebox.showerror("Error", "Failed to create session")
            else:
                messagebox.showerror("Error", "Invalid username or password!")
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            messagebox.showerror("Error", "An error occurred during login. Please try again.")
