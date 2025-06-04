import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from password_manager.encryption.key_manager import FernetKeyManager
from password_manager.utils.secure_data_utils import get_user_dir, get_backup_dir, ensure_directories_exist
from password_manager.auth.otp_service import OTPService
from .data_transfer import DataTransferManager

logger = logging.getLogger(__name__)


class BackupManager:
    def verify_backup_otp(self, otp: str) -> bool:
        """Проверка OTP-кода для резервного копирования текущего пользователя

        Args:
            otp: OTP-код для проверки

        Returns:
            bool: True если код действителен, False в противном случае
        """
        try:
            if not otp or len(otp.strip()) == 0:
                logger.warning("Предоставлен пустой OTP")
                return False

            return self.otp_service.verify_backup_otp(self.user_id, otp)
        except Exception as e:
            logger.error(f"Ошибка при проверке OTP для резервного копирования: {str(e)}")
            return False

    def generate_backup_otp(self, username: str):
        secret, qr_path = self.otp_service.generate_backup_otp(self.user_id, username)
        return secret, qr_path

    def __init__(self, user_id: int):
        self.user_id = user_id
        self.base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.key_manager = FernetKeyManager(self.base_dir, user_id)
        self.data_transfer = DataTransferManager(user_id, self.key_manager)
        self.otp_service = OTPService(self.base_dir, user_id)

        # Убедимся, что все директории существуют
        ensure_directories_exist(user_id)

        # Получим пользовательские директории
        self.user_dir = get_user_dir(user_id)
        self.backup_dir = get_backup_dir(user_id)

        # Загрузим историю резервных копий
        self.history_file = self.backup_dir / "backup_history.json"
        self.backup_history = self._load_backup_history()

        # Проверим, нужна ли ротация ключей
        if self.key_manager.should_rotate_key():
            self.key_manager.rotate_key()

    def _load_backup_history(self) -> dict:
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Не удалось загрузить историю резервных копий: {str(e)}")
                return {}
        return {}

    def _update_backup_history(self, filename: str, description: str):
        try:
            if not filename:  # Если файл пустой, просто выходим
                return

            file_path = self.backup_dir / filename

            # Проверяем, существует ли файл
            if not file_path.exists():
                logger.warning(f"Файл {filename} не существует, невозможно обновить историю")
                return

            # Создаем запись для истории
            self.backup_history[filename] = {
                "created_at": datetime.now().isoformat(),
                "description": description,
                "hash": self._calculate_file_hash(file_path)
            }

            # Сохраняем историю
            try:
                with open(self.history_file, 'w') as f:
                    json.dump(self.backup_history, f)
            except Exception as e:
                logger.error(f"Не удалось сохранить историю резервных копий: {str(e)}")
        except Exception as e:
            logger.error(f"Не удалось обновить историю резервных копий: {str(e)}")

    def _calculate_file_hash(self, file_path: Path) -> str:
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Не удалось рассчитать хеш файла для {file_path}: {str(e)}")
            # Возвращаем пустой хеш в случае ошибки
            return ""

    def _verify_backup_integrity(self, backup_path: Path) -> bool:
        try:
            filename = backup_path.name
            # Проверяем, есть ли файл в истории
            if filename not in self.backup_history:
                logger.warning(f"Резервная копия {filename} не найдена в истории")
                return False

            # Проверяем, что файл существует
            if not backup_path.exists():
                logger.warning(f"Файл резервной копии {filename} не существует")
                return False

            # Проверяем, является ли файл CSV (для них не делаем строгую проверку хеша)
            if filename.endswith('.csv'):
                logger.info(f"Обнаружен CSV-файл, пропускаем строгую проверку хеша для {filename}")
                return True

            # Для зашифрованных файлов делаем строгую проверку хеша
            current_hash = self._calculate_file_hash(backup_path)
            stored_hash = self.backup_history[filename]["hash"]

            # Если хеш пустой (ошибка при создании), возвращаем True для обратной совместимости
            if not stored_hash:
                logger.warning(f"Пустой хеш для {filename}, пропускаем проверку целостности")
                return True

            return current_hash == stored_hash
        except Exception as e:
            logger.error(f"Не удалось проверить целостность резервной копии: {str(e)}")
            return False

    def create_backup(self, otp: str, description: str, output_path: Optional[Path] = None, add_to_history: bool = True) -> Optional[Path]:
        try:
            # Проверяем OTP
            if not self.otp_service.verify_backup_otp(self.user_id, otp):
                logger.error("Недействительный OTP")
                return None

            # Создаем имя файла резервной копии с временной меткой
            if output_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_filename = f"backup_{timestamp}.enc"
                current_backup_path = self.backup_dir / backup_filename
            else:
                current_backup_path = output_path
                backup_filename = output_path.name # Needed for history if add_to_history is True

            # Экспортируем данные
            data = self.data_transfer.export_data()
            # Шифруем резервную копию
            encrypted_data = self.data_transfer.encrypt_export(data)

            # Сохраняем зашифрованную резервную копию
            current_backup_path.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
            with open(current_backup_path, "wb") as f:
                f.write(encrypted_data)

            # Обновляем историю резервных копий только если add_to_history True
            if add_to_history:
                self._update_backup_history(backup_filename, description)

            return current_backup_path
        except Exception as e:
            logger.error(f"Не удалось создать резервную копию: {str(e)}")
            return None

    def restore_backup(self, backup_name: str, otp: str) -> bool:
        try:
            # Проверяем OTP
            if not self.otp_service.verify_backup_otp(self.user_id, otp):
                logger.error("Недействительный OTP")
                return False

            backup_path = self.backup_dir / backup_name
            if not backup_path.exists():
                logger.error("Файл резервной копии не найден")
                return False

            # Проверяем целостность резервной копии
            if not self._verify_backup_integrity(backup_path):
                logger.error("Проверка целостности резервной копии не удалась")
                return False

            # Читаем зашифрованную резервную копию
            with open(backup_path, "rb") as f:
                encrypted_data = f.read()

            # Расшифровываем резервную копию
            decrypted_data = self.data_transfer.decrypt_import(encrypted_data)

            # Импортируем данные
            self.data_transfer.import_data(decrypted_data)

            return True
        except Exception as e:
            logger.error(f"Не удалось восстановить резервную копию: {str(e)}")
            return False

    def delete_backup(self, backup_id: str) -> bool:
        try:
            if backup_id not in self.backup_history:
                logger.warning(f"Резервная копия {backup_id} не найдена в истории")
                return False

            backup_path = self.backup_dir / backup_id

            # Сначала удаляем файл
            try:
                if backup_path.exists():
                    backup_path.unlink()
                    logger.info(f"Успешно удален файл резервной копии {backup_id}")

                # Удаляем из истории резервных копий
                del self.backup_history[backup_id]

                # Обновляем историю с информацией о последней резервной копии
                if self.backup_history:
                    last_backup = max(self.backup_history.items(), key=lambda x: x[1]['created_at'])
                    self._update_backup_history(last_backup[0], last_backup[1]['description'])
                else:
                    self._update_backup_history("", "")

                return True

            except Exception as e:
                logger.error(f"Не удалось удалить резервную копию {backup_id}: {str(e)}")
                return False

        except Exception as e:
            logger.error(f"Не удалось удалить резервную копию: {str(e)}")
            return False

    def get_backup_list(self) -> List[Dict[str, Any]]:
        backups = []
        for filename, info in self.backup_history.items():
            backup_path = self.backup_dir / filename
            if backup_path.exists():
                backups.append({
                    "name": filename,
                    "created_at": info["created_at"],
                    "description": info["description"]
                })
        return sorted(backups, key=lambda x: x["created_at"], reverse=True)

    def export_to_csv(self, otp: str, output_path: str = None) -> Tuple[bool, str]:
        """Экспорт паролей в формат CSV

        Args:
            otp: Одноразовый пароль для проверки
            output_path: Путь для сохранения CSV-файла. Если None, используется StringIO.

        Returns:
            Кортеж (успех, путь к файлу или сообщение об ошибке)
        """
        try:
            # Проверяем OTP для безопасности
            if not self.otp_service.verify_backup_otp(self.user_id, otp):
                logger.error("Недействительный OTP для экспорта CSV")
                return False, "Недействительный OTP"

            csv_content = self.data_transfer.export_data_to_csv()

            if output_path:
                # Сохраняем в файл
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    f.write(csv_content)
                logger.info(f"Успешно экспортированы пароли в CSV: {output_path}")
                return True, f"Экспорт завершен. Файл сохранен в {output_path}"
            else:
                # Возвращаем как строку (для использования в GUI)
                return True, csv_content

        except Exception as e:
            error_msg = f"Не удалось экспортировать в CSV: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def import_from_csv(self, otp: str, input_path: str) -> Tuple[bool, str]:
        """Импорт паролей из формата CSV

        Args:
            otp: Одноразовый пароль для проверки
            input_path: Путь к CSV-файлу для импорта

        Returns:
            Кортеж (успех, сообщение об успехе или ошибке)
        """
        try:
            # Проверяем OTP для безопасности
            if not self.otp_service.verify_backup_otp(self.user_id, otp):
                logger.error("Недействительный OTP для импорта CSV")
                return False, "Недействительный OTP"

            # Проверяем, существует ли файл
            if not os.path.exists(input_path):
                logger.error(f"CSV-файл не найден: {input_path}")
                return False, f"CSV-файл не найден: {input_path}"

            # Проверяем, что это CSV-файл
            if not input_path.lower().endswith('.csv'):
                logger.error(f"Файл не является CSV: {input_path}")
                return False, f"Файл не является CSV: {input_path}"

            # Импортируем данные
            imported_count = self.data_transfer.import_data_from_csv(input_path)
            
            logger.info(f"Успешно импортировано {imported_count} паролей из CSV: {input_path}")
            return True, f"Успешно импортировано {imported_count} паролей"

        except Exception as e:
            error_msg = f"Не удалось импортировать из CSV: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
