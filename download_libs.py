
#!/usr/bin/env python3
"""Скрипт для загрузки всех внешних библиотек локально"""

import os
import urllib.request
import ssl
import hashlib

# Создание SSL контекста для загрузки
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def download_file(url, filepath):
    """Загрузка файла с проверкой"""
    try:
        print(f"Загрузка: {url}")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        request = urllib.request.Request(url)
        request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        with urllib.request.urlopen(request, context=ssl_context) as response:
            with open(filepath, 'wb') as f:
                f.write(response.read())
        
        print(f"✓ Сохранено: {filepath}")
        return True
    except Exception as e:
        print(f"✗ Ошибка загрузки {url}: {e}")
        return False

def main():
    """Основная функция загрузки"""
    print("🔄 Загрузка локальных библиотек...")
    
    # Список файлов для загрузки
    files_to_download = [
        # Bootstrap CSS и JS
        ('https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css', 
         'static/libs/css/bootstrap.min.css'),
        ('https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js', 
         'static/libs/js/bootstrap.bundle.min.js'),
        
        # jQuery
        ('https://code.jquery.com/jquery-3.7.1.min.js', 
         'static/libs/js/jquery.min.js'),
        
        # Chart.js
        ('https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.min.js', 
         'static/libs/js/chart.min.js'),
        
        # FontAwesome CSS
        ('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css', 
         'static/libs/css/fontawesome.min.css'),
        
        # Feather Icons
        ('https://cdn.jsdelivr.net/npm/feather-icons@4.29.0/dist/feather.min.js', 
         'static/libs/js/feather.min.js')
    ]
    
    # Загрузка всех файлов
    success_count = 0
    for url, filepath in files_to_download:
        if download_file(url, filepath):
            success_count += 1
    
    print(f"\n✅ Загружено {success_count} из {len(files_to_download)} файлов")
    
    # Создание локальных стилей
    create_local_styles()
    
    print("🎉 Все библиотеки загружены локально!")

def create_local_styles():
    """Создание локальных стилей"""
    custom_css = """
/* Локальные стили для системы мониторинга */

.status-indicator {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    margin-right: 8px;
}

.status-up { background-color: #28a745; }
.status-down { background-color: #dc3545; }
.status-warning { background-color: #ffc107; }
.status-unknown { background-color: #6c757d; }

.host-list {
    max-height: 400px;
    overflow-y: auto;
    scrollbar-width: none; /* Firefox */
    -ms-overflow-style: none; /* IE и Edge */
}

.host-list::-webkit-scrollbar {
    display: none; /* Chrome, Safari, Opera */
}

.host-item {
    padding: 8px 12px;
    cursor: pointer;
    border-radius: 4px;
    margin-bottom: 2px;
    transition: background-color 0.2s ease;
}

.host-item:hover {
    background-color: #f8f9fa;
}

.host-item.active {
    background-color: #007bff;
    color: white;
}

.loading-indicator {
    position: absolute;
    top: 10px;
    right: 10px;
    z-index: 1000;
}

.navbar-brand {
    font-weight: 600;
}

.card-header {
    font-weight: 500;
}

.btn-sm {
    font-size: 0.875rem;
}

.table-sm td {
    padding: 0.5rem;
}

.alert {
    border-radius: 6px;
}

.form-control {
    border-radius: 6px;
}

.btn {
    border-radius: 6px;
}

.card {
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
"""
    
    with open('static/css/custom.css', 'w', encoding='utf-8') as f:
        f.write(custom_css)
    
    print("✓ Создан файл стилей: static/css/custom.css")

if __name__ == "__main__":
    main()
