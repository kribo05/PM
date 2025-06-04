import tkinter as tk
from tkinter import ttk, messagebox
from password_manager.utils.logging_config import setup_logging
import password_manager.auth.register as auth_register

logger = setup_logging()


class RegistrationWindow(tk.Toplevel):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.title("Register")
        self.geometry("400x450")
        self.resizable(False, False)
        self.controller = controller
        self.transient(parent)
        self.grab_set()
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
        self._create_widgets()
        self.bind("<Return>", lambda e: self.perform_registration())
        self.username_entry.focus()
    
    def _create_widgets(self):
        # Инструкции
        instructions = tk.Label(self, text="Password Requirements:\n\n"
                              "• At least 8 characters long\n"
                              "• Contains uppercase letters\n"
                              "• Contains lowercase letters\n"
                              "• Contains numbers\n"
                              "• Contains special characters (!@#$%^&*)", justify=tk.LEFT)
        instructions.pack(pady=10, padx=20)
        
        # Username
        user_frame = ttk.LabelFrame(self, text="Username")
        user_frame.pack(fill="x", padx=20, pady=10)
        
        self.username_entry = ttk.Entry(user_frame)
        self.username_entry.pack(fill="x", padx=10, pady=5)
        
        # Password
        pw_frame = ttk.LabelFrame(self, text="Password")
        pw_frame.pack(fill="x", padx=20, pady=10)
        
        self.password_entry = ttk.Entry(pw_frame, show="*")
        self.password_entry.pack(fill="x", padx=10, pady=5)
        
        # Подтверждение пароля
        confirm_frame = ttk.LabelFrame(self, text="Confirm Password")
        confirm_frame.pack(fill="x", padx=20, pady=10)
        
        self.confirm_entry = ttk.Entry(confirm_frame, show="*")
        self.confirm_entry.pack(fill="x", padx=10, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Button(button_frame, text="Register", command=self.perform_registration).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def perform_registration(self) -> None:
        try:
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            confirm = self.confirm_entry.get().strip()
            
            if not username or not password or not confirm:
                messagebox.showerror("Error", "All fields are required!")
                return
            
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match!")
                return

            # Используем UserRegistration из импортированного модуля
            if auth_register.UserRegistration.register_user(username, password):
                messagebox.showinfo("Success", "Registration successful! Please log in.")
                self.destroy()
                self.controller.show_frame("MenuP")
            else:
                messagebox.showerror("Error", "Registration failed. Username may already exist.")
                
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            messagebox.showerror("Error", "An error occurred during registration. Please try again.")
