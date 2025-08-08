#!/usr/bin/env python3
"""Скрипт запуска системы мониторинга с выбором сетевого интерфейса"""

import os
import sys
from network_interface import select_network_interface, print_available_interfaces

# Установка переменных для локального режима (если не установлены)
if 'REPL_ID' not in os.environ:
    os.environ['REPL_ID'] = 'local-dev-mode'
if 'SESSION_SECRET' not in os.environ:
    os.environ['SESSION_SECRET'] = 'local-dev-secret-key-change-in-production'

print("🚀 Система мониторинга хостов с выбором интерфейса")
print("📍 База данных: monitoring.db (создается автоматически в текущей папке)")
print("⚠️  Внимание: В локальном режиме аутентификация упрощена")
print("-" * 70)

# Показываем доступные интерфейсы и просим выбрать
try:
    selected_ip = select_network_interface()
except KeyboardInterrupt:
    print("\nЗапуск отменен пользователем.")
    sys.exit(0)

print(f"\nЗапуск сервера на IP: {selected_ip}:5000")
print(f"🌐 Адрес для доступа: http://{selected_ip}:5000")
print("=" * 50)

# Импорт и запуск приложения
try:
    from main import app
    if __name__ == "__main__":
        app.run(host=selected_ip, port=5000, debug=True, use_reloader=False)
except Exception as e:
    print(f"Ошибка запуска: {e}")
    sys.exit(1)