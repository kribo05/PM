import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class BackupSetupDialog(tk.Toplevel):
    def __init__(self, parent, qr_path: str):
        super().__init__(parent)
        self.title("Setup Backup Authentication")
        self.geometry("400x600")
        self.resizable(False, False)
        self.transient(parent)
        # self.grab_set() # Попробуем вызвать grab_set позже, после создания виджетов
        
        # Центрирование диалога
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
        
        self.qr_path = Path(qr_path)
        self.qr_photo = None  # Сохраняем ссылку, чтобы предотвратить сборку мусора
        
        # Откладываем создание виджетов и grab_set
        self.after(0, self._initialize_dialog_ui)

        # Привязка клавиши Enter для закрытия диалога
        self.bind("<Return>", lambda e: self.destroy())
        
        # Привязка события закрытия окна
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _initialize_dialog_ui(self):
        """Создает виджеты и устанавливает grab_set."""
        self._create_widgets()
        self.grab_set()  # Вызываем grab_set после того, как виджеты созданы
        # Убедимся, что фокус установлен после grab_set и создания виджетов
        if hasattr(self, 'ok_button'):  # Если есть кнопка OK/Close, на нее можно поставить фокус
             self.ok_button.focus_set()
        elif self.winfo_exists():  # Или на само окно, если оно еще существует
             self.focus_set()
    
    def _create_widgets(self):
        # Инструкции
        instructions = (
            "Setup two-factor authentication for backup management:\n\n"
            "1. Open your authenticator app (Google Authenticator, Microsoft Authenticator, etc.)\n"
            "2. Tap the + button to add a new account\n"
            "3. Choose 'Scan QR code'\n"
            "4. Scan the QR code below\n"
            "5. Enter the 6-digit code from your app when creating or restoring backups"
        )
        
        ttk.Label(
            self,
            text=instructions,
            wraplength=350,
            justify="left"
        ).pack(padx=20, pady=(20, 10))
        
        # QR-код
        try:
            if not self.qr_path.exists():
                logger.error(f"QR code file NOT FOUND at: {str(self.qr_path)}")
                raise FileNotFoundError(f"QR code file not found: {self.qr_path}")
            
            logger.info(f"Attempting to load QR image from: {str(self.qr_path)}")
            image = Image.open(self.qr_path)
            logger.info(f"PIL Image.open successful. Image object: {image}, Format: {image.format}, Size: {image.size}, Mode: {image.mode}")
            
            # Расчет размера для размещения в окне с сохранением пропорций
            max_size = 300
            ratio = min(max_size/image.width, max_size/image.height)
            new_size = (int(image.width*ratio), int(image.height*ratio))
            image = image.resize(new_size, Image.Resampling.LANCZOS)
            logger.info(f"PIL Image.resize successful. New size: {image.size}")
            
            # Преобразование в PhotoImage
            self.qr_photo = ImageTk.PhotoImage(image, master=self)
            logger.info(f"ImageTk.PhotoImage successful. Object: {self.qr_photo}")
            
            # Создание метки с QR-кодом
            qr_label = tk.Label(self, image=self.qr_photo)
            qr_label.pack(pady=20)
            
            # Добавление примечания о резервных кодах
            backup_note = (
                "Important: This authentication is only used for backup management.\n"
                "You will need to enter the code when creating or restoring backups."
            )
            ttk.Label(
                self,
                text=backup_note,
                wraplength=350,
                justify="center",
                foreground="red"
            ).pack(pady=10)
            
        except Exception as e:
            logger.error(f"Failed to load QR code: {str(e)}")
            messagebox.showerror("Error", f"Failed to load QR code: {str(e)}")
            self.destroy()
            return
        
        # Кнопка закрытия
        self.ok_button = ttk.Button(
            self,
            text="I've scanned the QR code",
            command=self.destroy
        )
        self.ok_button.pack(pady=20)
