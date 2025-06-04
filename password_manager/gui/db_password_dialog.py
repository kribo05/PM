import tkinter as tk
from tkinter import ttk, messagebox
from password_manager.utils.logging_config import setup_logging
from password_manager.config import Config
from password_manager.security.password_security import PasswordSecurity

logger = setup_logging()


class DatabasePasswordDialog:
    def __init__(self, parent, is_new_key: bool = True):
        self.parent = parent
        self.result = None
        self.config = Config()
        self.is_new_key = is_new_key
        
        # Создание диалогового окна
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Database Passphrase")
        self.dialog.grab_set()  # Делаем окно модальным
        self.dialog.resizable(False, False)  # Отключаем изменение размера
        
        # Центрирование диалога
        window_width = 400
        window_height = 400 if is_new_key else 200  # Меньше высота для существующего ключа
        screen_width = self.dialog.winfo_screenwidth()
        screen_height = self.dialog.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Создание основного фрейма с отступами
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        if is_new_key:
            # Требования для нового пароля
            requirements_text = (
                "Database Passphrase Requirements:\n\n"
                "• At least 12 characters long\n"
                "• Contains uppercase letters (A-Z)\n"
                "• Contains lowercase letters (a-z)\n"
                "• Contains numbers (0-9)\n"
                "• Contains special characters (!@#$%^&*)\n\n"
                "This passphrase will directly encrypt the database.\n"
                "Please choose a strong passphrase and keep it safe!"
            )
            
            requirements_label = ttk.Label(
                main_frame, 
                text=requirements_text,
                justify=tk.LEFT,
                wraplength=350
            )
            requirements_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky="w")
        else:
            # Сообщение для существующего ключа
            message_text = "Please enter the database passphrase to unlock the database."
            message_label = ttk.Label(
                main_frame,
                text=message_text,
                justify=tk.LEFT,
                wraplength=350
            )
            message_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky="w")
        
        # Фрейм для ввода пароля
        pw_frame = ttk.LabelFrame(
            main_frame, 
            text="Enter Database Passphrase" if not is_new_key else "Create Database Passphrase",
            padding="10"
        )
        pw_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(pw_frame, textvariable=self.password_var, show="*", width=40)
        self.password_entry.grid(row=0, column=0, pady=5, padx=5, sticky="ew")
        
        if is_new_key:
            # Фрейм для подтверждения пароля (только для нового ключа)
            confirm_frame = ttk.LabelFrame(main_frame, text="Confirm Password", padding="10")
            confirm_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 20))
            
            self.confirm_var = tk.StringVar()
            self.confirm_entry = ttk.Entry(confirm_frame, textvariable=self.confirm_var, show="*", width=40)
            self.confirm_entry.grid(row=0, column=0, pady=5, padx=5, sticky="ew")
        else:
            self.confirm_var = None
        
        # Фрейм для кнопок
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=3 if is_new_key else 2, column=0, columnspan=2, pady=(0, 10))
        
        ttk.Button(btn_frame, text="OK", command=self.ok_clicked, width=15).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.cancel_clicked, width=15).grid(row=0, column=1, padx=5)
        
        # Настройка высоты сетки
        main_frame.columnconfigure(0, weight=1)
        pw_frame.columnconfigure(0, weight=1)
        if is_new_key:
            confirm_frame.columnconfigure(0, weight=1)
        
        # Установка фокуса
        self.password_entry.focus()
        
        # Привязка клавиши Enter
        self.dialog.bind('<Return>', lambda e: self.ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())
        
        # Ожидание закрытия диалога
        parent.wait_window(self.dialog)
    
    def _validate_password(self, password: str) -> tuple[bool, str]:
        """Проверка надежности пароля с использованием PasswordSecurity."""
        if not self.is_new_key:  # Пропускаем проверку для существующего ключа (если пароль не создается заново)
            return True, "Password validation skipped for existing key." 
            
        return PasswordSecurity.validate_password(password)  # Используем централизованный метод
    
    def ok_clicked(self):
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        
        if self.is_new_key:
            confirm = self.confirm_var.get()
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return
        
        valid, message = self._validate_password(password)
        if not valid:
            messagebox.showerror("Error", message)
            return
        
        self.result = password
        self.dialog.destroy()
    
    def cancel_clicked(self):
        self.result = None
        self.dialog.destroy()
    
    @staticmethod
    def get_password(parent, is_new_key: bool = True):
        dialog = DatabasePasswordDialog(parent, is_new_key)
        return dialog.result
