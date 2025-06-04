import tkinter as tk
from tkinter import ttk
from password_manager.gui.login_window import LoginWindow
import pyperclip
import os
import threading
import time

# Получение пути к директории с ресурсами
ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets')


def mask_password(password):
    return "*****"


def copy_to_clipboard(text):
    """Копирование текста в буфер обмена и очистка через 12 секунд"""
    pyperclip.copy(text)

    def clear_clipboard():
        time.sleep(12)   # Ожидание 12 секунд
        pyperclip.copy('')  # Очистка буфера обмена
    # Запуск таймера в отдельном потоке
    threading.Thread(target=clear_clipboard, daemon=True).start()


def ask_for_pw(parent, controller):
    """Открытие окна входа"""
    LoginWindow(parent, controller)


class SecondWindow(tk.Toplevel):
    """Базовый класс для вторичных окон"""
    def __init__(self, parent, title, geometry, propagate):
        super().__init__(parent)
        self.title(title)
        self.geometry(geometry)
        self.propagate(propagate)
        self.resizable(False, False)
        self.iconbitmap(os.path.join(ASSETS_DIR, "icon.ico"))


def create_scrollable_frame(parent):
    """Создание прокручиваемого фрейма с холстом и полосой прокрутки"""
    canvas = tk.Canvas(parent)
    scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    return canvas, scrollbar, scrollable_frame
