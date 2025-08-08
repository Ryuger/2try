import sqlite3
import subprocess
import threading
import time
import logging
from datetime import datetime
from app import db

def get_db_connection():
    """Подключение к базе данных SQLite для мониторинга."""
    conn = sqlite3.connect("monitoring.db")
    conn.row_factory = sqlite3.Row
    return conn

def get_groups():
    """Получение списка групп из базы данных."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT group_name FROM groups")
        groups = [row['group_name'] for row in cursor.fetchall()]
    except sqlite3.Error:
        groups = []
    finally:
        conn.close()
    return groups

def get_subgroups(group_name):
    """Получение списка подгрупп в группе."""
    if not group_name:
        return ['Все']
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Используем безопасное экранирование имени таблицы
        table_name = "hosts_" + group_name.replace("'", "''")
        cursor.execute(f"SELECT DISTINCT subgroup FROM '{table_name}' WHERE subgroup IS NOT NULL")
        subgroups = [row['subgroup'] for row in cursor.fetchall()]
        return ['Все'] + subgroups if subgroups else ['Все']
    except sqlite3.Error:
        return ['Все']
    finally:
        conn.close()

def get_hosts(group_name, subgroup=None):
    """Получение списка хостов в группе с фильтром по подгруппе."""
    if not group_name:
        return []
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Безопасное экранирование имени таблицы
        table_name = "hosts_" + group_name.replace("'", "''")
        query = f"SELECT address, description, subgroup FROM '{table_name}'"
        params = []
        if subgroup and subgroup != 'Все':
            query += " WHERE subgroup = ?"
            params.append(subgroup)
        cursor.execute(query, params)
        hosts = []
        for row in cursor.fetchall():
            hosts.append({
                'address': row['address'], 
                'description': row['description'], 
                'subgroup': row['subgroup'] or 'нет'
            })
    except sqlite3.Error:
        hosts = []
    finally:
        conn.close()
    return hosts

def get_ping_history(group_name, address, start_time=None, end_time=None, status=None, subgroup=None):
    """Получение истории пингов для хоста с фильтром по подгруппе."""
    if not group_name or not address:
        return []
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT timestamp, status, latency FROM ping_results WHERE group_name = ? AND address = ?"
        params = [group_name, address]
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        if status:
            query += " AND status = ?"
            params.append(status)
        if subgroup and subgroup != 'Все':
            # Безопасное экранирование имени таблицы
            table_name = "hosts_" + group_name.replace("'", "''")
            cursor.execute(f"SELECT subgroup FROM '{table_name}' WHERE address = ?", (address,))
            host_subgroup = cursor.fetchone()
            if host_subgroup and host_subgroup[0] != subgroup:
                return []
        
        query += " ORDER BY timestamp DESC LIMIT 1000"
        cursor.execute(query, params)
        history = []
        for row in cursor.fetchall():
            history.append({
                'timestamp': row['timestamp'], 
                'status': row['status'], 
                'latency': row['latency'] if row['latency'] is not None else 'нет данных'
            })
    except sqlite3.Error:
        history = []
    finally:
        conn.close()
    return history

def get_dashboard_data(group_name, subgroup=None):
    """Получение данных для дашборда с фильтром по подгруппе."""
    if not group_name:
        return {'availability': [], 'latency': [], 'down': []}
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Получение списка хостов
        table_name = "hosts_" + group_name.replace("'", "''")
        query = f"SELECT address FROM '{table_name}'"
        params = []
        if subgroup and subgroup != 'Все':
            query += " WHERE subgroup = ?"
            params.append(subgroup)
        cursor.execute(query, params)
        hosts = [row['address'] for row in cursor.fetchall()]
        
        # Процент доступности хостов
        availability_data = []
        for address in hosts:
            cursor.execute(
                "SELECT status, COUNT(*) as count FROM ping_results WHERE group_name = ? AND address = ? GROUP BY status",
                (group_name, address)
            )
            total = 0
            up_count = 0
            for row in cursor.fetchall():
                total += row['count']
                if row['status'] == 'Доступен':
                    up_count += row['count']
            availability = (up_count / total * 100) if total > 0 else 0
            availability_data.append({'address': address, 'availability': round(availability, 2)})
        
        # Средняя задержка для доступных хостов
        query = "SELECT address, AVG(latency) as avg_latency FROM ping_results WHERE group_name = ? AND status = 'Доступен' GROUP BY address"
        params = [group_name]
        if subgroup and subgroup != 'Все':
            table_name = "hosts_" + group_name.replace("'", "''")
            cursor.execute(f"SELECT address FROM '{table_name}' WHERE subgroup = ?", (subgroup,))
            host_addresses = [row[0] for row in cursor.fetchall()]
            if host_addresses:
                query += " AND address IN ({})".format(','.join('?' * len(host_addresses)))
                params.extend(host_addresses)
        cursor.execute(query, params)
        latency_data = []
        for row in cursor.fetchall():
            latency_data.append({
                'address': row['address'], 
                'avg_latency': round(row['avg_latency'], 3) if row['avg_latency'] is not None else 0
            })
        
        # Количество недоступных хостов по времени (последние 24 часа)
        query = """
        SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, COUNT(*) as down_count 
        FROM ping_results 
        WHERE group_name = ? AND status = 'Недоступен' 
        AND datetime(timestamp) >= datetime('now', '-24 hours')
        GROUP BY hour 
        ORDER BY hour
        """
        params = [group_name]
        if subgroup and subgroup != 'Все':
            table_name = "hosts_" + group_name.replace("'", "''")
            cursor.execute(f"SELECT address FROM '{table_name}' WHERE subgroup = ?", (subgroup,))
            host_addresses = [row[0] for row in cursor.fetchall()]
            if host_addresses:
                query = query.replace("GROUP BY hour", "AND address IN ({}) GROUP BY hour".format(','.join('?' * len(host_addresses))))
                params.extend(host_addresses)
        cursor.execute(query, params)
        down_data = []
        for row in cursor.fetchall():
            down_data.append({'timestamp': row['hour'], 'down_count': row['down_count']})
        
    except sqlite3.Error as e:
        logging.error(f"Database error in get_dashboard_data: {e}")
        availability_data = []
        latency_data = []
        down_data = []
    finally:
        conn.close()
    
    return {'availability': availability_data, 'latency': latency_data, 'down': down_data}

def get_host_status_color(group_name, address):
    """Получить цвет статуса хоста для UI"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Получить последний статус
        cursor.execute(
            "SELECT status FROM ping_results WHERE group_name = ? AND address = ? ORDER BY timestamp DESC LIMIT 1",
            (group_name, address)
        )
        result = cursor.fetchone()
        if result:
            return 'success' if result['status'] == 'Доступен' else 'danger'
        return 'secondary'
    except sqlite3.Error:
        return 'secondary'
    finally:
        conn.close()

def get_subgroup_status_summary(group_name, subgroup):
    """Получить сводку статуса подгруппы"""
    hosts = get_hosts(group_name, subgroup)
    if not hosts:
        return {'total': 0, 'up': 0, 'down': 0, 'status': 'secondary'}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    up_count = 0
    down_count = 0
    
    try:
        for host in hosts:
            cursor.execute(
                "SELECT status FROM ping_results WHERE group_name = ? AND address = ? ORDER BY timestamp DESC LIMIT 1",
                (group_name, host['address'])
            )
            result = cursor.fetchone()
            if result:
                if result['status'] == 'Доступен':
                    up_count += 1
                else:
                    down_count += 1
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    
    total = len(hosts)
    if up_count == total:
        status = 'success'
    elif down_count == total:
        status = 'danger'
    else:
        status = 'warning'
    
    return {
        'total': total,
        'up': up_count,
        'down': down_count,
        'status': status
    }
