from tkinter import ttk, messagebox
from password_manager.database.database_manager import DatabaseManager
from password_manager.encryption import EncryptionService
from password_manager.gui.backup_window import BackupWindow
import tkinter as tk
from password_manager.gui.utils import copy_to_clipboard, mask_password
import os


class Secret(tk.Frame):
    def __init__(self, parent, controller, user_id=None):
        super().__init__(parent)
        self.tree = None
        self.site_entry = None
        self.username_entry = None
        self.password_entry = None
        self.search_entry = None
        self.controller = controller
        self.user_id = user_id
        self.last_added_id = None
        self.db_manager = DatabaseManager()
        self.session_manager = controller.session_manager
        self.encryption_service = EncryptionService(base_dir=os.path.dirname(self.db_manager.db_path))
        self.init_ui()
        self.bind("<<ShowFrame>>", self.on_show_frame)
    
    def init_ui(self):
        # Create main container
        container = tk.Frame(self)
        container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create title
        title = tk.Label(container, text="Password Manager", font=("Helvetica", 24, "bold"))
        title.pack(pady=10)
        
        # Create search frame
        search_frame = ttk.LabelFrame(container, text="Search")
        search_frame.pack(fill="x", padx=5, pady=5)
        
        # Add search entry
        ttk.Label(search_frame, text="Site:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, padx=5, pady=5, fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self.on_search)
        
        # Create input frame
        input_frame = ttk.LabelFrame(container, text="Add/Edit Password")
        input_frame.pack(fill="x", padx=5, pady=5)
        
        # Username entry
        ttk.Label(input_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(input_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Site entry
        ttk.Label(input_frame, text="Site:").grid(row=0, column=2, padx=5, pady=5)
        self.site_entry = ttk.Entry(input_frame)
        self.site_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Password entry
        ttk.Label(input_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(input_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=2, column=0, columnspan=4, pady=10)
        
        ttk.Button(button_frame, text="Add", command=self.add_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit", command=self.edit_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=self.delete_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_entries).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Backup", command=self.open_backup_manager).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Back", command=self.back_to_menu).pack(side=tk.LEFT, padx=5)
        
        # Create treeview
        self.tree = ttk.Treeview(container, columns=("Username", "Site", "Password"), show="headings")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Site", text="Site")
        self.tree.heading("Password", text="Password")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind events
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def open_backup_manager(self):
        if self.controller.validate_session():
            # Получаем username пользователя из базы данных
            username = self.db_manager.get_username_by_id(self.user_id)
            if not username:
                messagebox.showerror("Error", "Failed to get user information")
                return
            
            try:
                # Обновляем сессию перед открытием окна резервных копий
                if hasattr(self.controller, 'session_manager') and hasattr(self.controller, 'current_session'):
                    if self.controller.refresh_token:
                        new_access_token, new_refresh_token = self.controller.session_manager.refresh_session_token(
                            self.controller.refresh_token
                        )
                        if new_access_token and new_refresh_token:
                            self.controller.current_session = new_access_token
                            self.controller.refresh_token = new_refresh_token
                            BackupWindow(self, user_id=self.user_id, username=username, on_restore_callback=self.refresh_table)
                        else:
                            messagebox.showerror("Error", "Session expired. Please log in again.")
                            self.controller.show_frame("MenuP")
                    else:
                        messagebox.showerror("Error", "Invalid session state. Please log in again.")
                        self.controller.show_frame("MenuP")
                else:
                    # Fallback if session manager isn't available
                    BackupWindow(self, user_id=self.user_id, username=username, on_restore_callback=self.refresh_table)
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error opening backup window: {str(e)}")
                messagebox.showerror("Error", f"Failed to open backup window: {str(e)}")
                self.controller.show_frame("MenuP")
    
    def refresh_table(self, search_term=None):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        if self.user_id:
            # Если есть поисковый запрос, используем индекс по site
            if search_term:
                passwords = self.db_manager.search_passwords_by_site(self.user_id, search_term)
            else:
                # Если нет поискового запроса, получаем только последний добавленный пароль
                # или ничего, если last_added_id не установлен
                passwords = self.db_manager.get_user_passwords(self.user_id)
                
                # Если нет last_added_id, ничего не показываем
                if not self.last_added_id:
                    return
            
            for pwd in passwords:
                # Получаем данные из словаря (Row)
                pwd_id = pwd['id']
                username = pwd['username']
                site = pwd['site']
                encrypted_password = pwd['password']
                
                # Если нет поискового запроса и это не последний добавленный элемент, пропускаем
                if not search_term and pwd_id != self.last_added_id:
                    continue
                
                decrypted_password = self.decrypt_password(encrypted_password)
                self.tree.insert("", "end", values=(username, site, mask_password(decrypted_password)), tags=(str(pwd_id), decrypted_password))
    
    def add_password(self):
        username = self.username_entry.get().strip()
        site = self.site_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not all([username, site, password]):
            messagebox.showerror("Error", "All fields must be filled!")
            return
        
        self.last_added_id = self.db_manager.add_password(self.user_id, username, site, password)
        if self.last_added_id:
            self.clear_entries()
            self.refresh_table()
        else:
            messagebox.showerror("Error", "Failed to add password!")
    
    def edit_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to edit!")
            return
        
        pwd_id = self.tree.item(selected[0])["tags"][0]
        username = self.username_entry.get().strip()
        site = self.site_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not all([username, site, password]):
            messagebox.showerror("Error", "All fields must be filled!")
            return
        
        if self.db_manager.update_password(pwd_id, username, site, password, self.user_id):
            self.clear_entries()
            self.refresh_table(self.search_entry.get().strip())
        else:
            messagebox.showerror("Error", "Failed to update password!")
    
    def delete_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to delete!")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this password?"):
            pwd_id = self.tree.item(selected[0])["tags"][0]
            if self.db_manager.delete_password(pwd_id):
                self.clear_entries()
                self.refresh_table(self.search_entry.get().strip())
            else:
                messagebox.showerror("Error", "Failed to delete password!")
    
    def clear_entries(self):
        self.username_entry.delete(0, tk.END)
        self.site_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
    
    def back_to_menu(self):
        self.controller.show_frame("MenuP")
    
    def on_double_click(self, event):
        selected = self.tree.selection()
        if selected:
            item = self.tree.item(selected[0])
            values = item["values"]
            tags = item["tags"]
            self.username_entry.delete(0, tk.END)
            self.username_entry.insert(0, values[0])
            self.site_entry.delete(0, tk.END)
            self.site_entry.insert(0, values[1])
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, tags[1])  # Use actual password from tags
    
    def show_context_menu(self, event):
        selected = self.tree.identify_row(event.y)
        if selected:
            self.tree.selection_set(selected)
            item = self.tree.item(selected)
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Copy Password", command=lambda: copy_to_clipboard(item["tags"][1]))
            menu.post(event.x_root, event.y_root)
    
    def on_search(self, event):
        search_term = self.search_entry.get().strip()
        self.refresh_table(search_term)
    
    def on_show_frame(self, event):
        if self.user_id:
            self.search_entry.delete(0, tk.END)  # Clear search on frame show
            self.refresh_table()

    def decrypt_password(self, encrypted_password: str) -> str:
        """Расшифровывает пароль"""
        return self.encryption_service.decrypt_password(encrypted_password, self.user_id)
