
#!/usr/bin/env python3
"""Главный файл для запуска системы мониторинга с локальной аутентификацией"""

import os
import sys

# Установка переменных для локального режима
os.environ['REPL_ID'] = 'local-dev-mode'
os.environ['SESSION_SECRET'] = 'local-dev-secret-key-change-in-production'

print("🚀 Система мониторинга хостов с локальной аутентификацией")
print("📍 База данных: monitoring.db (создается автоматически)")
print("👤 Суперадмин: superadmin / admin123")
print("⚠️  Внимание: Работает с локальной аутентификацией и IP фильтрацией")
print("-" * 70)

# Импорт приложения
from app import app
from auth import auth_manager

# Импорт всех маршрутов
import routes

if __name__ == '__main__':
    print("🌐 Запуск на http://0.0.0.0:5000")
    print("🔐 Логин: superadmin, Пароль: admin123")
    print("=" * 70)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
