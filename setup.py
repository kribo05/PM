from setuptools import setup, find_packages

setup(
    name="password_manager",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'sqlcipher3-wheels>=0.5.4',
        'python-dotenv==1.0.0',
        'cryptography==42.0.5',
        'humanize==4.9.0',
        'qrcode==7.4.2',
        'pyotp==2.9.0',
        'Pillow==10.2.0',
        'setuptools>=65.5.1',
        'config>=0.5.1',
        'argon2-cffi>=21.3.0',
        'ttkthemes>=3.2.2',
        'pyperclip>=1.8.2',
        'PyJWT>=2.8.0',
    ],
)
