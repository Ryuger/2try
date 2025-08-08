#!/usr/bin/env python3
"""Скрипт для локального запуска системы мониторинга без Replit Auth"""

import os
import sys
from network_interface import get_default_interface, print_available_interfaces

# Установка переменных для локального режима
os.environ['REPL_ID'] = 'local-dev-mode'
os.environ['SESSION_SECRET'] = 'local-dev-secret-key-change-in-production'

print("🚀 Запуск системы мониторинга хостов в локальном режиме...")
print("📍 База данных: monitoring.db (создается автоматически в текущей папке)")

# Получаем IP по умолчанию для информации
default_ip = get_default_interface()

print(f"🌐 Адрес: http://{default_ip}:5000")
print("⚠️  Внимание: Аутентификация отключена в локальном режиме")
print("-" * 60)

# Показать доступные интерфейсы
print_available_interfaces()
print(f"\n💡 Для выбора другого интерфейса используйте: python run_with_interface.py")
print("=" * 60)

# Импорт и запуск приложения
from main import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)