import tkinter as tk
from password_manager.gui.login_window import LoginWindow
from password_manager.gui.registration_window import RegistrationWindow


class MenuP(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        # Создание контейнера для виджетов
        container = tk.Frame(self)
        container.pack(expand=True, fill="both")
        
        # Создание заголовка
        title = tk.Label(container, text="Password Manager", font=("Helvetica", 24, "bold"))
        title.pack(pady=20)
        
        # Create buttons frame
        button_frame = tk.Frame(container)
        button_frame.pack(pady=20)
        
        # Create buttons
        login_button = tk.Button(button_frame, text="Login", command=self.open_login, width=15, height=2)
        login_button.pack(side=tk.LEFT, padx=10)
        
        register_button = tk.Button(button_frame, text="Register", command=self.open_registration, width=15, height=2)
        register_button.pack(side=tk.LEFT, padx=10)
    
    def open_login(self):
        LoginWindow(self, self.controller)
    
    def open_registration(self):
        RegistrationWindow(self, self.controller)
