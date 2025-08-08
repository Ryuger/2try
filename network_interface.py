#!/usr/bin/env python3
"""Модуль для работы с сетевыми интерфейсами"""

import netifaces
import sys


def get_network_interfaces():
    """Получение списка сетевых интерфейсов и их IP-адресов."""
    interfaces = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                netmask = addr['netmask']
                interfaces.append({
                    'name': iface,
                    'ip': ip,
                    'netmask': netmask,
                    'id': iface if iface != 'lo' else 'lo'
                })
    return interfaces


def select_network_interface():
    """Запрос у пользователя выбора сетевого интерфейса."""
    interfaces = get_network_interfaces()
    if not interfaces:
        print("Ошибка: Не найдены сетевые интерфейсы.")
        sys.exit(1)
    
    print("\n=== Система мониторинга хостов ===")
    print("Выберите сетевой интерфейс для запуска сервера:\n")
    
    for i, iface in enumerate(interfaces, 1):
        if iface['name'] == 'lo':
            print(f"{i}. {iface['id']} - {iface['ip']} (Localhost - только локальный доступ)")
        else:
            print(f"{i}. {iface['id']} - {iface['ip']} (IPv4: {iface['ip']}/{iface['netmask']})")
    
    while True:
        try:
            choice = int(input("\nВведите номер интерфейса (1-{}): ".format(len(interfaces))))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice-1]['ip']
            else:
                print(f"Неверный выбор. Пожалуйста, выберите число от 1 до {len(interfaces)}.")
        except ValueError:
            print("Ошибка: Введите число.")
        except KeyboardInterrupt:
            print("\nОтмена запуска.")
            sys.exit(0)


def get_default_interface():
    """Получение IP по умолчанию (первый не-localhost интерфейс)."""
    interfaces = get_network_interfaces()
    for iface in interfaces:
        if iface['ip'] != '127.0.0.1':
            return iface['ip']
    # Если нет других интерфейсов, используем localhost
    return '127.0.0.1'


def print_available_interfaces():
    """Вывод доступных интерфейсов без выбора."""
    interfaces = get_network_interfaces()
    print("\nДоступные сетевые интерфейсы:")
    for i, iface in enumerate(interfaces, 1):
        if iface['name'] == 'lo':
            print(f"  {i}. {iface['id']} - {iface['ip']} (Localhost)")
        else:
            print(f"  {i}. {iface['id']} - {iface['ip']} (IPv4: {iface['ip']}/{iface['netmask']})")