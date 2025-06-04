import PyInstaller.__main__
import os
import sys
import shutil
from distutils.sysconfig import get_python_lib
import platform
import site

# Проверка архитектуры
IS_64BITS = platform.architecture()[0] == '64bit'

# Пути к зависимостям
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLCIPHER_PATH = os.path.join(BASE_DIR, "dependencies", "crypto", "sqlcipher")
DEPENDENCIES_PATH = os.path.join(BASE_DIR, "dependencies")

# Получаем путь к DLL из пакета sqlcipher3-wheels
def find_sqlcipher_dll():
    for path in site.getsitepackages():
        dll_path = os.path.join(path, 'sqlcipher3_wheels', 'sqlite3.dll')
        if os.path.exists(dll_path):
            return dll_path
    return None

# Встроенные DLL файлы
BUNDLED_DLLS = {
    'sqlite3.dll': find_sqlcipher_dll() or os.path.join(DEPENDENCIES_PATH, 'crypto', 'sqlcipher', 'sqlcipher-4.7.0', 'sqlite3.dll'),
    'libcrypto-3-x64.dll': os.path.join(DEPENDENCIES_PATH, 'crypto/openssl', 'libcrypto-3-x64.dll'),
    'libssl-3-x64.dll': os.path.join(DEPENDENCIES_PATH, 'crypto/openssl', 'libssl-3-x64.dll')
}

# Проверяем наличие всех DLL
def verify_dlls():
    missing_dlls = []
    for dll_name, dll_path in BUNDLED_DLLS.items():
        if not os.path.exists(dll_path):
            missing_dlls.append(dll_path)
    
    if missing_dlls:
        print("ERROR: Missing required DLL files:")
        for dll in missing_dlls:
            print(f"  - {dll}")
        sys.exit(1)
def copy_dlls():
    # Создаем директорию для DLL в корневой папке
    dist_path = os.path.join(BASE_DIR, 'dist')
    os.makedirs(dist_path, exist_ok=True)
    
    # Копируем все необходимые DLL
    success = True
    for dll_name, dll_path in BUNDLED_DLLS.items():
        if os.path.exists(dll_path):
            target_path = os.path.join(dist_path, dll_name)
            try:
                shutil.copy2(dll_path, target_path)
                print(f"Скопировано: {dll_name} -> {target_path}")
                # Проверяем, что файл действительно скопировался
                if not os.path.exists(target_path):
                    raise Exception(f"DLL не была скопирована: {target_path}")
            except Exception as e:
                print(f"Ошибка при копировании {dll_name}: {e}")
                success = False
        else:
            print(f"Ошибка: {dll_path} не найден!")
            success = False
    
    return success

def get_sqlcipher_path():
    site_packages = get_python_lib()
    return os.path.join(site_packages, "pysqlcipher3")

def main():
    # Проверяем наличие DLL
    verify_dlls()
    
    # Очищаем старые файлы сборки в корневой папке
    for dir_name in ['build', 'dist']:
        root_path = os.path.join(BASE_DIR, dir_name)
        script_path = os.path.join(os.path.dirname(__file__), dir_name)
        
        if os.path.exists(root_path):
            shutil.rmtree(root_path)
        if os.path.exists(script_path):
            shutil.rmtree(script_path)
    
    # Получаем путь к pysqlcipher3
    sqlcipher_path = get_sqlcipher_path()
    
    # Проверяем наличие основного файла
    main_script = os.path.join(BASE_DIR, 'password_manager', '__main__.py')
    if not os.path.exists(main_script):
        print(f"ERROR: Main script not found: {main_script}")
        sys.exit(1)
    
    print("\nПути к файлам:")
    print(f"Main script: {main_script}")
    print(f"SQLite3 DLL: {BUNDLED_DLLS['sqlite3.dll']}")
    print(f"Crypto DLL: {BUNDLED_DLLS['libcrypto-3-x64.dll']}")
    print(f"SSL DLL: {BUNDLED_DLLS['libssl-3-x64.dll']}\n")
    
    # Параметры для PyInstaller
    # Создаем папку dist в корневой директории
    dist_path = os.path.join(BASE_DIR, 'dist')
    os.makedirs(dist_path, exist_ok=True)

    # Получаем путь к DLL SQLite
    sqlite_dll = BUNDLED_DLLS['sqlite3.dll']
    if not os.path.exists(sqlite_dll):
        print(f"ERROR: SQLite DLL not found at {sqlite_dll}")
        sys.exit(1)
    else:
        print(f"Using SQLite DLL from: {sqlite_dll}")

    PyInstaller.__main__.run([
        os.path.join(BASE_DIR, 'password_manager', '__main__.py'),
        '--onefile',
        '--noconsole',
        '--windowed',
        '--distpath', dist_path,
        '--workpath', os.path.join(BASE_DIR, 'build'),
        '--specpath', BASE_DIR,
        '--paths', BASE_DIR,
        '--hidden-import', 'sqlcipher3_wheels',
        '--hidden-import', 'sqlcipher3_wheels.dbapi2',
        '--hidden-import', 'password_manager.auth.login',
        '--hidden-import', 'password_manager.database.database_manager',
        '--hidden-import', 'password_manager.gui.menu_window',
        '--hidden-import', 'password_manager.gui.main_window',
        '--hidden-import', 'password_manager.database.models',
        '--hidden-import', 'password_manager.auth.register',
        '--hidden-import', 'tkinter',
        '--hidden-import', '_tkinter',
        '--hidden-import', 'tkinter.ttk',
        '--hidden-import', 'tkinter.messagebox',
        '--hidden-import', 'ttkthemes',
        '--hidden-import', 'cryptography',
        '--hidden-import', 'win32security',
        '--hidden-import', 'pywin32',
        '--hidden-import', 'password_manager.config',
        '--hidden-import', 'password_manager.security',
        '--hidden-import', 'password_manager.security.session',
        '--hidden-import', 'password_manager.security.windows_permissions',
        '--additional-hooks-dir', 'PyInstaller/hooks',
        '--add-binary', f'{sqlite_dll};.',
        '--add-binary', f'{BUNDLED_DLLS["libcrypto-3-x64.dll"]};.',
        '--add-binary', f'{BUNDLED_DLLS["libssl-3-x64.dll"]};.',
        '--add-data', f'{os.path.dirname(sqlite_dll)};sqlcipher3_wheels',
        '--name', 'password_manager',
        '--clean',
        '--uac-admin'
    ])

if __name__ == '__main__':
    try:
        main()
        # Копируем DLL файлы после сборки
        if copy_dlls():
            print("\nСборка успешно завершена!")
            print("Исполняемый файл находится в папке dist/")
        else:
            print("\nСборка завершена с ошибками при копировании DLL!")
            sys.exit(1)
    except Exception as e:
        print(f"\nОшибка при сборке: {e}")
        sys.exit(1)
