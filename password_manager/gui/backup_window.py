"""
Окно управления резервными копиями
"""

import logging
import re
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, simpledialog, filedialog

import humanize

from password_manager.backup.backup_manager import BackupManager
from password_manager.database.database_manager import DatabaseManager
from password_manager.gui.backup_setup_dialog import BackupSetupDialog
from password_manager.utils.secure_data_utils import ensure_directories_exist

logger = logging.getLogger(__name__)


class BackupWindow(tk.Toplevel):
    def __init__(self, parent, user_id: int, username: str, on_restore_callback=None):
        super().__init__(parent)
        # Получаем session_manager из контроллера
        self.parent = parent
        self.controller = parent.controller if hasattr(parent, 'controller') else None
        self.session_manager = self.controller.session_manager if self.controller else None

        self.title("Управление резервными копиями")
        self.geometry("800x600")  # Увеличиваем размер окна
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # Центрируем окно
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

        self.user_id = user_id
        self.username = username
        self.backup_manager = BackupManager(user_id)
        self.on_restore_callback = on_restore_callback

        # Проверяем наличие всех директорий
        ensure_directories_exist(user_id)

        # Настраиваем таймер обновления
        self.refresh_interval = 60000  # 1 минута в миллисекундах
        self.setup_refresh_timer()

        # Проверяем, настроен ли OTP
        if not self.backup_manager.otp_service.is_otp_enabled(user_id):
            self._setup_otp()

        self._create_widgets()

    def setup_refresh_timer(self):
        """Настройка таймера для периодического обновления сессионного токена"""
        if self.controller and self.session_manager:
            self.after(self.refresh_interval, self.refresh_session)

    def refresh_session(self):
        """Обновление сессионного токена"""
        try:
            if self.controller and hasattr(self.controller, 'current_session'):
                current_token = self.controller.current_session
                refresh_token = self.controller.refresh_token
                if current_token and refresh_token:
                    new_access_token, new_refresh_token = self.session_manager.refresh_session_token(refresh_token)
                    if new_access_token and new_refresh_token:
                        self.controller.current_session = new_access_token
                        self.controller.refresh_token = new_refresh_token
                        logger.debug("Сессионный токен успешно обновлен")
                    else:
                        logger.warning("Не удалось обновить сессионный токен")
                        messagebox.showerror("Сессия истекла", "Ваша сессия истекла. Пожалуйста, войдите снова.")
                        self.destroy()
                        self.controller.show_frame("MenuP")
                        return

            # Планируем следующее обновление
            self.after(self.refresh_interval, self.refresh_session)
        except Exception as e:
            logger.error(f"Ошибка при обновлении сессии: {str(e)}")
            self.destroy()
            self.controller.show_frame("MenuP")

    def _check_otp_setup(self) -> bool:
        """Проверка, настроен ли OTP для пользователя"""
        try:
            return self.backup_manager.otp_service.is_otp_enabled(self.user_id)
        except Exception as e:
            logger.error(f"Не удалось проверить настройку OTP: {str(e)}")
            return False

    def _create_widgets(self):
        # Основной контейнер с отступами
        main_container = ttk.Frame(self, padding="10")
        main_container.pack(fill="both", expand=True)

        # Фрейм справки
        help_frame = ttk.Frame(main_container)
        help_frame.pack(fill="x", pady=(0, 5))

        ttk.Button(
            help_frame,
            text="Инструкция",
            command=self._show_help
        ).pack(side="right")

        # Фрейм OTP
        otp_frame = ttk.LabelFrame(main_container, text="Двухфакторная аутентификация")
        otp_frame.pack(fill="x", pady=(0, 5))

        ttk.Label(
            otp_frame,
            text="Введите код:"
        ).pack(side="left", padx=5)

        self.otp_entry = ttk.Entry(otp_frame, width=10, show="*")
        self.otp_entry.pack(side="left", padx=5)

        ttk.Button(
            otp_frame,
            text="Проверить",
            command=self._verify_otp
        ).pack(side="left", padx=5)

        # Фрейм кнопок
        buttons_frame = ttk.Frame(main_container)
        buttons_frame.pack(fill="x", pady=(0, 5))

        self.create_button = ttk.Button(
            buttons_frame,
            text="Создать резервную копию",
            command=self._create_backup,
            state="disabled"
        )
        self.create_button.pack(side="left", padx=5)

        self.restore_button = ttk.Button(
            buttons_frame,
            text="Восстановить",
            command=self._restore_backup,
            state="disabled"
        )
        self.restore_button.pack(side="left", padx=5)

        # Кнопки экспорта/импорта
        self.export_button = ttk.Button(
            buttons_frame,
            text="Экспорт",
            command=self._export_data,
            state="disabled"
        )
        self.export_button.pack(side="left", padx=5)

        self.import_button = ttk.Button(
            buttons_frame,
            text="Импорт",
            command=self._import_data,
            state="disabled"
        )
        self.import_button.pack(side="left", padx=5)

        # Фрейм списка резервных копий
        self.list_frame = ttk.LabelFrame(main_container, text="Доступные резервные копии")
        self.list_frame.pack(fill="both", expand=True, pady=(0, 5))

        # Создаем Treeview
        columns = ("Дата", "Описание", "Размер")
        self.backup_tree = ttk.Treeview(self.list_frame, columns=columns, show="headings")

        # Настраиваем заголовки столбцов
        self.backup_tree.heading("Дата", text="Дата")
        self.backup_tree.heading("Описание", text="Описание")
        self.backup_tree.heading("Размер", text="Размер")

        # Устанавливаем ширину столбцов
        self.backup_tree.column("Дата", width=150)
        self.backup_tree.column("Описание", width=500)  # Увеличиваем ширину колонки описания
        self.backup_tree.column("Размер", width=100)

        # Добавляем полосу прокрутки
        scrollbar = ttk.Scrollbar(self.list_frame, orient="vertical", command=self.backup_tree.yview)
        self.backup_tree.configure(yscrollcommand=scrollbar.set)

        # Размещаем Treeview и полосу прокрутки
        self.backup_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Фрейм кнопки удаления
        delete_frame = ttk.Frame(main_container)
        delete_frame.pack(fill="x", pady=(0, 5))

        self.delete_button = ttk.Button(
            delete_frame,
            text="Удалить выбранную копию",
            command=self._delete_backup,
            state="disabled"
        )
        self.delete_button.pack(expand=True)

        # Изначально скрываем список резервных копий
        self.list_frame.pack_forget()
        self.delete_button.pack_forget()

    def check_session(self):
        """Проверка действительности текущей сессии"""
        if self.controller and hasattr(self.controller, 'current_session'):
            if self.session_manager and not self.session_manager.is_valid_session(self.controller.current_session):
                messagebox.showerror("Сессия истекла", "Ваша сессия истекла. Пожалуйста, войдите снова.")
                self.destroy()
                self.controller.show_frame("MenuP")
                return False
        return True

    def _setup_otp(self):
        """Настройка одноразового пароля (OTP) для резервного копирования"""
        try:
            # Проверяем, настроен ли уже OTP
            if self.backup_manager.otp_service.is_otp_enabled(self.user_id):
                qr_path = self.backup_manager.otp_service.get_qr_path(self.user_id)
                if qr_path:
                    # Показываем существующий QR-код
                    dialog = BackupSetupDialog(self, qr_path)
                    self.wait_window(dialog)
                    return

            # Сбрасываем существующие OTP-файлы
            self.backup_manager.otp_service.reset_otp(self.user_id)

            # Генерируем OTP и QR-код
            secret, qr_path = self.backup_manager.generate_backup_otp(self.username)
            if not secret or not qr_path:
                raise Exception("Не удалось сгенерировать OTP")

            # Показываем диалог настройки QR-кода
            dialog = BackupSetupDialog(self, qr_path)
            self.wait_window(dialog)

        except Exception as e:
            logger.error(f"Не удалось настроить OTP: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось настроить двухфакторную аутентификацию: {str(e)}")
            self.destroy()

    def _get_valid_otp(self):
        """Получение и проверка OTP-кода"""
        otp = self.otp_entry.get().strip()
        if not otp:
            messagebox.showerror("Ошибка", "Введите код аутентификации")
            return None

        if not self.backup_manager.verify_backup_otp(otp):
            messagebox.showerror("Ошибка", "Неверный код аутентификации")
            return None

        return otp

    def _verify_otp_and_get_code(self):
        """Проверка OTP и получение кода, если он действителен"""
        return self._get_valid_otp()

    def _verify_otp(self):
        """Проверка введенного OTP-кода и активация кнопок при успешной проверке"""
        try:
            # Проверяем сессию
            if not self.check_session():
                return

            otp = self.otp_entry.get().strip()
            if not otp:
                messagebox.showerror("Ошибка", "Введите код из приложения аутентификации")
                return

            if self.backup_manager.verify_backup_otp(otp):
                messagebox.showinfo("Успех", "Код верифицирован")

                # Активируем кнопки
                self.create_button.config(state="normal")
                self.restore_button.config(state="normal")
                self.export_button.config(state="normal")
                self.import_button.config(state="normal")

                # Отображаем список резервных копий
                self.list_frame.pack(fill="both", expand=True, pady=(0, 5))
                self.delete_button.pack(expand=True)

                # Обновляем список резервных копий
                self._refresh_backup_list()
            else:
                messagebox.showerror("Ошибка", "Неверный код аутентификации")
        except Exception as e:
            logger.error(f"Ошибка при проверке OTP: {str(e)}")
            messagebox.showerror("Ошибка", f"Ошибка проверки кода: {str(e)}")

    def _create_backup(self):
        """Создание новой резервной копии"""
        try:
            # Проверяем сессию
            if not self.check_session():
                return

            # Получаем OTP
            otp_code = self._get_valid_otp()
            if not otp_code:
                return

            # Запрашиваем описание
            description = simpledialog.askstring("Описание резервной копии", "Введите описание для этой резервной копии:")
            if not description:
                return

            # Создаем резервную копию
            created_path = self.backup_manager.create_backup(otp_code, description)

            if created_path:
                messagebox.showinfo("Успех", "Резервная копия успешно создана!")
                self._refresh_backup_list()
            else:
                messagebox.showerror("Ошибка", "Не удалось создать резервную копию!")
        except Exception as e:
            logger.error(f"Ошибка при создании резервной копии: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось создать резервную копию: {str(e)}")

    def _get_selected_backup(self):
        """Получение выбранной резервной копии"""
        selected_items = self.backup_tree.selection()
        if not selected_items:
            messagebox.showerror("Ошибка", "Выберите резервную копию")
            return None

        item_id = selected_items[0]
        backup_id = self.backup_tree.item(item_id, "values")[0]

        return backup_id

    def _restore_backup(self):
        """Восстановление данных из выбранной резервной копии"""
        try:
            # Проверяем сессию
            if not self.check_session():
                return

            # Получаем OTP
            otp_code = self._get_valid_otp()
            if not otp_code:
                return

            # Получаем выбранную резервную копию
            backup_id = self._get_selected_backup()
            if not backup_id:
                return

            # Запрашиваем подтверждение
            if not messagebox.askyesno("Подтверждение",
                                   "Восстановление заменит все текущие данные.\n\n"
                                   "Продолжить?"):
                return

            # Находим имя файла резервной копии
            backup_name = None
            for backup in self.backup_manager.get_backup_list():
                if backup["created_at"] == backup_id:
                    backup_name = backup["name"]
                    break

            if not backup_name:
                messagebox.showerror("Ошибка", "Резервная копия не найдена")
                return

            # Восстанавливаем из резервной копии
            success = self.backup_manager.restore_backup(backup_name, otp_code)

            if success:
                messagebox.showinfo("Успех", "Данные успешно восстановлены!")
                if self.on_restore_callback:
                    self.on_restore_callback()
            else:
                messagebox.showerror("Ошибка", "Не удалось восстановить данные!")

        except Exception as e:
            logger.error(f"Ошибка при восстановлении из резервной копии: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось восстановить данные: {str(e)}")

    def _delete_backup(self):
        """Удаление выбранной резервной копии"""
        try:
            # Проверяем сессию
            if not self.check_session():
                return

            # Получаем OTP
            otp = self._get_valid_otp()
            if not otp:
                return

            # Получаем выбранную резервную копию
            selected_items = self.backup_tree.selection()
            if not selected_items:
                messagebox.showerror("Ошибка", "Выберите резервную копию для удаления")
                return

            item_id = selected_items[0]
            item_values = self.backup_tree.item(item_id, "values")
            backup_date = item_values[0]  # Переименовываем date_str в backup_date
            desc = item_values[1]

            # Находим имя файла резервной копии
            backup_name = None
            for backup in self.backup_manager.get_backup_list():
                if backup["created_at"] == backup_date:  # Используем backup_date
                    backup_name = backup["name"]
                    break

            if not backup_name:
                messagebox.showerror("Ошибка", "Резервная копия не найдена")
                return

            # Запрашиваем подтверждение
            if not messagebox.askyesno("Подтверждение",
                                   f"Вы уверены, что хотите удалить:\n\n"
                                   f"Дата: {backup_date}\n"
                                   f"Описание: {desc}\n\n"
                                   f"Это действие нельзя отменить."):
                return

            # Удаляем резервную копию
            success = self.backup_manager.delete_backup(backup_name)

            if success:
                messagebox.showinfo("Успех", "Резервная копия успешно удалена!")
                self._refresh_backup_list()
            else:
                messagebox.showerror("Ошибка", "Не удалось удалить резервную копию!")

        except Exception as e:
            logger.error(f"Ошибка при удалении резервной копии: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось удалить резервную копию: {str(e)}")

    def _refresh_backup_list(self):
        """Обновление списка доступных резервных копий"""
        try:
            # Очищаем текущий список
            for item in self.backup_tree.get_children():
                self.backup_tree.delete(item)

            # Получаем список резервных копий
            backups = self.backup_manager.get_backup_list()

            # Заполняем список
            for backup in backups:
                try:
                    # Преобразуем ISO формат даты в читаемый вид
                    dt = datetime.fromisoformat(backup["created_at"])
                    date_str = dt.strftime("%Y-%m-%d %H:%M:%S")

                    # Получаем размер файла
                    import os
                    from pathlib import Path

                    backup_path = Path(self.backup_manager.backup_dir) / backup["name"]
                    if backup_path.exists():
                        size_bytes = os.path.getsize(backup_path)
                        size_str = humanize.naturalsize(size_bytes)
                    else:
                        size_str = "N/A"

                    # Добавляем в дерево
                    self.backup_tree.insert("", "end", values=(backup["created_at"], backup["description"], size_str))
                except Exception as e:
                    logger.error(f"Ошибка при обработке резервной копии {backup['name']}: {str(e)}")
                    continue
        except Exception as e:
            logger.error(f"Ошибка при обновлении списка резервных копий: {str(e)}")

    def _export_data(self):
        print("DEBUG: _export_data called (CSV ONLY)")
        """Экспорт данных только в формате CSV"""
        if not self._check_otp_setup():
            messagebox.showerror("Ошибка", "OTP не настроен. Пожалуйста, настройте OTP сначала.")
            return

        # Получаем OTP
        otp_code = self._get_valid_otp()
        print(f"DEBUG: otp_code in _export_data (CSV ONLY): {otp_code}")
        if not otp_code:
            return

        # Логика экспорта сразу в CSV (взята из предыдущей рабочей версии)
        try:
            # Показываем предупреждение о безопасности
            if not messagebox.askyesno(
                "Предупреждение о безопасности",
                "ВНИМАНИЕ! CSV файл будет содержать пароли в открытом виде!\n\n"
                "Это небезопасно! Убедитесь, что вы:\n"
                "1. Сохраняете файл в безопасном месте\n"
                "2. Удалите файл сразу после использования\n"
                "3. Не передаете файл третьим лицам\n\n"
                "Продолжить экспорт?",
                icon="warning"
            ):
                return
            
            # Диалог сохранения для CSV
            file_path = filedialog.asksaveasfilename(
                parent=self,
                title="Сохранить как CSV",
                defaultextension=".csv",
                filetypes=[("CSV файлы", "*.csv"), ("Все файлы", "*.*")],
                initialfile="passwords.csv",
                confirmoverwrite=True
            )
            
            if not file_path:
                return
                
            # Принудительно добавляем расширение .csv, если его нет
            if not file_path.lower().endswith('.csv'):
                file_path = f"{file_path}.csv"
                
            success, result = self.backup_manager.export_to_csv(otp_code, file_path)

            if success:
                messagebox.showinfo(
                    "Успех", 
                    f"{result}\n\n"
                    "ВАЖНО: Файл содержит пароли в открытом виде!\n"
                    "Рекомендуется удалить его сразу после использования.",
                    icon="warning"
                )
            else:
                messagebox.showerror("Ошибка", f"Ошибка экспорта: {result}")

        except Exception as e:
            logger.error(f"Ошибка экспорта CSV: {str(e)}")
            messagebox.showerror("Ошибка", f"Ошибка экспорта CSV: {str(e)}")

    def _show_help(self):
        """Показываем диалог справки с инструкциями по резервному копированию"""
        help_text = """
Инструкция по работе с резервными копиями:

1. Первоначальная настройка:
   - При первом входе отсканируйте QR-код в приложении (Яндекс.Ключ/Google Authenticator для получения ключа
   - Это нужно сделать только один раз

2. Создание резервной копии:
   - Введите код 
   - Нажмите 'Проверить'
   - Нажмите 'Создать резервную копию'
   - Введите описание копии

3. Восстановление из резервной копии:
   - Введите код 
   - Нажмите 'Проверить'
   - Выберите копию из списка
   - Нажмите 'Восстановить'

4. Экспорт данных:
   - Введите код 
   - Нажмите 'Проверить'
   - Нажмите 'Экспорт'
   - Выберите формат экспорта:
     а) Зашифрованная резервная копия - для использования в этом приложении
     б) CSV (открытый текст) - для импорта в другие менеджеры паролей
   - Выберите место сохранения файла

5. Импорт данных из файла:
   - Введите код
   - Нажмите 'Проверить'
   - Нажмите 'Импорт'
   - Выберите файл для импорта
   - Подтвердите замену текущих данных

Важно:
- Всегда проверяйте код перед операциями
- Храните резервные копии в безопасном месте
- При импорте все текущие данные будут заменены
- CSV файлы содержат пароли в открытом виде - удаляйте их после использования!
"""
        messagebox.showinfo("Инструкция по резервному копированию", help_text)

    def _import_data(self):
        """Импорт данных только из CSV файла"""
        # print("DEBUG: _import_data called (CSV ONLY)") # Удалено
        try:
            # Проверяем сессию
            if not self.check_session():
                return

            # Запрашиваем OTP
            otp = self.otp_entry.get().strip()
            if not otp or not self.backup_manager.verify_backup_otp(otp):
                messagebox.showerror("Ошибка", "Введите действительный код из приложения аутентификации")
                return
            
            # print(f"DEBUG: otp_code in _import_data (CSV ONLY): {otp}") # Удалено

            # Сразу вызываем логику импорта CSV
            self._import_csv(otp)

        except Exception as e:
            logger.error(f"Ошибка при импорте данных (CSV ONLY): {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось импортировать данные: {str(e)}")

    def _import_encrypted_backup(self, otp):
        """Импорт данных из зашифрованного файла резервной копии"""
        try:
            # Получаем местоположение файла
            file_path = filedialog.askopenfilename(
                filetypes=[("Password Manager Backup", "*.pmbackup")],
                title="Выберите файл для импорта"
            )
            if not file_path:
                return

            # Запрашиваем подтверждение импорта
            if not messagebox.askyesno(
                "Подтверждение",
                "Импорт заменит все ваши существующие пароли. Продолжить?"
            ):
                return

            # Читаем и расшифровываем файл
            try:
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {str(e)}")
                return

            # Расшифровываем и импортируем данные
            try:
                decrypted_data = self.backup_manager.data_transfer.decrypt_import(encrypted_data)
                success = self.backup_manager.data_transfer.import_data(decrypted_data)
                if success:
                    messagebox.showinfo("Успех", "Данные успешно импортированы")
                    # Вызываем callback функцию для обновления GUI
                    if self.on_restore_callback:
                        self.on_restore_callback()
                else:
                    messagebox.showerror("Ошибка", "Не удалось импортировать данные")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось расшифровать или импортировать данные: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to import encrypted backup: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось импортировать данные: {str(e)}")

    def _import_csv(self, otp):
        """Импорт паролей из файла CSV"""
        try:
            # Получаем местоположение файла
            file_path = filedialog.askopenfilename(
                title="Открыть CSV",
                filetypes=[("CSV files", "*.csv")],
                initialfile="passwords.csv"
            )
            if not file_path:
                return

            # Показываем информацию о формате CSV
            info_message = (
                "CSV файл должен содержать следующие столбцы:\n"
                "• Site - адрес сайта или название сервиса\n"
                "• Username - имя пользователя или логин\n"
                "• Password - пароль\n\n"
                "Поддерживаемые форматы:\n"
                "• Кодировка: UTF-8, UTF-8 с BOM, Windows-1251\n"
                "• Разделители: запятая (,) или точка с запятой (;)\n\n"
                "Импортированные пароли будут добавлены\n"
                "к существующим паролям.\n\n"
                "Продолжить импорт?"
            )

            if not messagebox.askyesno("Информация об импорте", info_message):
                return

            # Импортируем данные
            success, result = self.backup_manager.import_from_csv(otp, file_path)

            if success:
                # Получаем ID последнего импортированного пароля
                try:
                    # Извлекаем количество импортированных паролей из сообщения
                    match = re.search(r'(\d+)', result)
                    if match:
                        num_imported = int(match.group(1))
                        if num_imported > 0:
                            # Получаем последний пароль из базы для этого пользователя
                            db_manager = DatabaseManager()
                            last_password = db_manager.get_last_password(self.user_id)

                            # Если callback установлен, передаем в него ID последнего пароля
                            if self.on_restore_callback and last_password:
                                # Устанавливаем переменную last_added_id в Secret window
                                parent_frame = self.parent
                                if hasattr(parent_frame, 'last_added_id'):
                                    parent_frame.last_added_id = last_password['id']
                except Exception as e:
                    logger.warning(f"Не удалось получить последний импортированный пароль: {str(e)}")

                messagebox.showinfo(
                    "Успех",
                    f"{result}\nПоследний импортированный пароль будет показан в списке."
                )

                # Вызываем callback для обновления списка паролей
                if self.on_restore_callback:
                    self.on_restore_callback()
            else:
                messagebox.showerror("Ошибка", result)

        except Exception as e:
            logger.error(f"Ошибка при импорте CSV: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось импортировать данные: {str(e)}")
