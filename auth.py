import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, redirect, url_for, flash, render_template
from cryptography.fernet import Fernet
import json
import os

class LocalAuth:
    def __init__(self, app=None):
        self.app = app
        self.crypto_key = self._get_or_create_crypto_key()
        self.fernet = Fernet(self.crypto_key)
        self.users_file = 'config/users.json'
        self.sessions_file = 'config/sessions.json'

        # Создание папки config если не существует
        os.makedirs('config', exist_ok=True)

        # Создание суперадмина по умолчанию
        self._create_default_superadmin()

        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.auth = self

    def _get_or_create_crypto_key(self):
        """Получение или создание ключа шифрования"""
        key_file = 'config/crypto.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key

    def _encrypt_data(self, data):
        """Шифрование данных"""
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(self.fernet.encrypt(data)).decode()

    def _decrypt_data(self, encrypted_data):
        """Расшифровка данных"""
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            return self.fernet.decrypt(decoded_data).decode()
        except:
            return None

    def _hash_password(self, password, salt=None):
        """Хэширование пароля"""
        if salt is None:
            salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${password_hash.hex()}"

    def _verify_password(self, password, stored_hash):
        """Проверка пароля"""
        try:
            salt, hash_hex = stored_hash.split('$')
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hash_hex == password_hash.hex()
        except:
            return False

    def _load_users(self):
        """Загрузка пользователей"""
        if not os.path.exists(self.users_file):
            return {}
        try:
            with open(self.users_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}

    def _save_users(self, users):
        """Сохранение пользователей"""
        with open(self.users_file, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)

    def _create_default_superadmin(self):
        """Создание суперадмина по умолчанию"""
        users = self._load_users()
        if not any(user.get('role') == 'superadmin' for user in users.values()):
            admin_id = 'superadmin'
            users[admin_id] = {
                'username': 'superadmin',
                'password_hash': self._hash_password('admin123'),
                'role': 'superadmin',
                'created_at': datetime.now().isoformat(),
                'is_active': True,
                'last_login': None
            }
            self._save_users(users)

    def create_user(self, username, password, role='user', created_by=None):
        """Создание пользователя"""
        users = self._load_users()

        # Проверка уникальности имени пользователя
        if any(user.get('username') == username for user in users.values()):
            return False, "Пользователь с таким именем уже существует"

        user_id = secrets.token_hex(16)
        users[user_id] = {
            'username': username,
            'password_hash': self._hash_password(password),
            'role': role,
            'created_at': datetime.now().isoformat(),
            'created_by': created_by,
            'is_active': True,
            'last_login': None
        }

        self._save_users(users)
        return True, "Пользователь создан успешно"

    def authenticate_user(self, username, password):
        """Аутентификация пользователя"""
        users = self._load_users()

        for user_id, user_data in users.items():
            if (user_data.get('username') == username and 
                user_data.get('is_active', True) and
                self._verify_password(password, user_data.get('password_hash', ''))):

                # Обновление времени последнего входа
                users[user_id]['last_login'] = datetime.now().isoformat()
                self._save_users(users)

                return True, {
                    'user_id': user_id,
                    'username': username,
                    'role': user_data.get('role', 'user'),
                }

        return False, None

    def get_user_by_id(self, user_id):
        """Получение пользователя по ID"""
        users = self._load_users()
        user_data = users.get(user_id)

        if user_data:
            return {
                'user_id': user_id,
                'username': user_data.get('username'),
                'role': user_data.get('role', 'user'),
                'created_at': user_data.get('created_at'),
                'last_login': user_data.get('last_login'),
                'is_active': user_data.get('is_active', True)
            }
        return None

    def get_all_users(self):
        """Получение всех пользователей (для админов)"""
        users = self._load_users()
        result = []

        for user_id, user_data in users.items():
            result.append({
                'user_id': user_id,
                'username': user_data.get('username'),
                'role': user_data.get('role', 'user'),
                'created_at': user_data.get('created_at'),
                'last_login': user_data.get('last_login'),
                'is_active': user_data.get('is_active', True),
                'created_by': user_data.get('created_by')
            })

        return result

    def update_user(self, user_id, **kwargs):
        """Обновление данных пользователя"""
        users = self._load_users()

        if user_id not in users:
            return False, "Пользователь не найден"

        if 'password' in kwargs:
            users[user_id]['password_hash'] = self._hash_password(kwargs['password'])
            del kwargs['password']

        for key, value in kwargs.items():
            if key in ['role', 'is_active']:
                users[user_id][key] = value

        self._save_users(users)
        return True, "Данные пользователя обновлены"

    def delete_user(self, user_id):
        """Удаление пользователя"""
        users = self._load_users()

        if user_id not in users:
            return False, "Пользователь не найден"

        # Нельзя удалить последнего суперадмина
        if users[user_id].get('role') == 'superadmin':
            superadmin_count = sum(1 for u in users.values() if u.get('role') == 'superadmin' and u.get('is_active'))
            if superadmin_count <= 1:
                return False, "Нельзя удалить последнего суперадмина"

        del users[user_id]
        self._save_users(users)
        return True, "Пользователь удален"

# Глобальная переменная для аутентификации
auth_manager = LocalAuth()

def login_required(f):
    """Декоратор для проверки аутентификации"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Необходимо войти в систему', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Декоратор для проверки прав администратора"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Необходимо войти в систему', 'warning')
            return redirect(url_for('login'))

        user = auth_manager.get_user_by_id(session['user_id'])
        if not user or user['role'] not in ['admin', 'superadmin']:
            flash('Недостаточно прав доступа', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    """Декоратор для проверки прав суперадминистратора"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Необходимо войти в систему', 'warning')
            return redirect(url_for('login'))

        user = auth_manager.get_user_by_id(session['user_id'])
        if not user or user['role'] != 'superadmin':
            flash('Недостаточно прав доступа', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Получение текущего пользователя"""
    if 'user_id' in session:
        return auth_manager.get_user_by_id(session['user_id'])
    return None