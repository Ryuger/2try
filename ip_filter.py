import json
import os
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, render_template, g, session

class IPFilter:
    def __init__(self):
        self.whitelist_file = 'config/whitelist.json'
        self.blacklist_file = 'config/blacklist.json'
        self.attempts_file = 'config/attempts.json'
        self.max_attempts = 3
        self.lockout_duration = timedelta(hours=24)
        
        # Создание папки config если не существует
        os.makedirs('config', exist_ok=True)
        
        # Создание файлов по умолчанию
        self._create_default_files()
    
    def _create_default_files(self):
        """Создание файлов по умолчанию"""
        if not os.path.exists(self.whitelist_file):
            default_whitelist = {
                "allowed_ips": ["127.0.0.1", "::1", "localhost"]
            }
            with open(self.whitelist_file, 'w') as f:
                json.dump(default_whitelist, f, indent=2)
        
        if not os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, 'w') as f:
                json.dump({"blocked_ips": []}, f, indent=2)
        
        if not os.path.exists(self.attempts_file):
            with open(self.attempts_file, 'w') as f:
                json.dump({}, f, indent=2)
    
    def load_whitelist(self):
        """Загрузка белого списка"""
        try:
            with open(self.whitelist_file, 'r') as f:
                data = json.load(f)
                return data.get('allowed_ips', [])
        except:
            return ["127.0.0.1", "::1", "localhost"]
    
    def load_blacklist(self):
        """Загрузка черного списка"""
        try:
            with open(self.blacklist_file, 'r') as f:
                data = json.load(f)
                return data.get('blocked_ips', [])
        except:
            return []
    
    def save_blacklist(self, blacklist):
        """Сохранение черного списка"""
        try:
            with open(self.blacklist_file, 'w') as f:
                json.dump({"blocked_ips": blacklist}, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving blacklist: {e}")
    
    def load_attempts(self):
        """Загрузка попыток доступа"""
        try:
            with open(self.attempts_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def save_attempts(self, attempts):
        """Сохранение попыток доступа"""
        try:
            with open(self.attempts_file, 'w') as f:
                json.dump(attempts, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving attempts: {e}")
    
    def get_client_ip(self, request):
        """Получение IP клиента"""
        # Проверяем заголовки прокси
        if request.headers.getlist("X-Forwarded-For"):
            return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr
    
    def is_ip_whitelisted(self, ip):
        """Проверка IP в белом списке"""
        whitelist = self.load_whitelist()
        return ip in whitelist or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.')
    
    def is_ip_blacklisted(self, ip):
        """Проверка IP в черном списке"""
        blacklist = self.load_blacklist()
        return ip in blacklist
    
    def add_failed_attempt(self, ip):
        """Добавление неудачной попытки"""
        attempts = self.load_attempts()
        now = datetime.now().isoformat()
        
        if ip not in attempts:
            attempts[ip] = {
                'count': 1,
                'first_attempt': now,
                'last_attempt': now
            }
        else:
            attempts[ip]['count'] += 1
            attempts[ip]['last_attempt'] = now
        
        # Если превышено количество попыток - добавить в черный список
        if attempts[ip]['count'] >= self.max_attempts:
            blacklist = self.load_blacklist()
            if ip not in blacklist:
                blacklist.append(ip)
                self.save_blacklist(blacklist)
                logging.warning(f"IP {ip} blocked after {self.max_attempts} failed attempts")
        
        self.save_attempts(attempts)
        logging.warning(f"Unauthorized attempt {attempts[ip]['count']}/{self.max_attempts}: {ip}")
    
    def check_ip_access(self, ip):
        """Проверка доступа для IP"""
        # Проверка черного списка
        if self.is_ip_blacklisted(ip):
            return False, "IP заблокирован"
        
        # Проверка белого списка
        if not self.is_ip_whitelisted(ip):
            return False, "IP не в белом списке"
        
        return True, "OK"

# Глобальный экземпляр фильтра
ip_filter = IPFilter()

def require_ip_whitelist(f):
    """Декоратор для проверки IP в белом списке"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = ip_filter.get_client_ip(request)
        
        # Проверка доступа
        access_allowed, reason = ip_filter.check_ip_access(client_ip)
        
        if not access_allowed:
            # Добавляем неудачную попытку только если IP не в белом списке
            if reason == "IP не в белом списке":
                ip_filter.add_failed_attempt(client_ip)
            
            # Показываем страницу блокировки
            from auth import get_current_user
            return render_template("blocked.html", 
                                 client_ip=client_ip, 
                                 reason=reason,
                                 current_user=get_current_user()), 403
        
        return f(*args, **kwargs)
    return decorated_function

class IPFilter:
    def __init__(self):
        self.whitelist_file = 'config/whitelist.json'
        self.blacklist_file = 'config/blacklist.json'
        self.attempts_file = 'config/attempts.json'
        self.max_attempts = 3
        
    def load_whitelist(self):
        """Load whitelist from JSON file"""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    data = json.load(f)
                    return data.get('allowed_ips', [])
        except Exception as e:
            logging.error(f"Error loading whitelist: {e}")
        return []
    
    def load_blacklist(self):
        """Load blacklist from JSON file"""
        try:
            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, 'r') as f:
                    data = json.load(f)
                    return data.get('blocked_ips', [])
        except Exception as e:
            logging.error(f"Error loading blacklist: {e}")
        return []
    
    def save_blacklist(self, blacklist):
        """Save blacklist to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.blacklist_file), exist_ok=True)
            with open(self.blacklist_file, 'w') as f:
                json.dump({'blocked_ips': blacklist}, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving blacklist: {e}")
    
    def load_attempts(self):
        """Load attempt counter from JSON file"""
        try:
            if os.path.exists(self.attempts_file):
                with open(self.attempts_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Error loading attempts: {e}")
        return {}
    
    def save_attempts(self, attempts):
        """Save attempt counter to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.attempts_file), exist_ok=True)
            with open(self.attempts_file, 'w') as f:
                json.dump(attempts, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving attempts: {e}")
    
    def get_client_ip(self):
        """Get client IP address, handling proxies"""
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr
    
    def is_ip_allowed(self, ip):
        """Check if IP is in whitelist"""
        whitelist = self.load_whitelist()
        return ip in whitelist or ip == '127.0.0.1' or ip == 'localhost'
    
    def is_ip_blocked(self, ip):
        """Check if IP is in blacklist JSON file"""
        blacklist = self.load_blacklist()
        return ip in blacklist
    
    def record_attempt(self, ip):
        """Record unauthorized attempt and block if limit exceeded"""
        attempts = self.load_attempts()
        
        if ip not in attempts:
            attempts[ip] = {
                'count': 1,
                'first_attempt': datetime.now().isoformat(),
                'last_attempt': datetime.now().isoformat()
            }
        else:
            attempts[ip]['count'] += 1
            attempts[ip]['last_attempt'] = datetime.now().isoformat()
        
        self.save_attempts(attempts)
        
        # If max attempts reached, add to blacklist
        if attempts[ip]['count'] >= self.max_attempts:
            blacklist = self.load_blacklist()
            if ip not in blacklist:
                blacklist.append(ip)
                self.save_blacklist(blacklist)
                logging.warning(f"IP blocked after {self.max_attempts} attempts: {ip}")
                return True  # Blocked
        
        logging.warning(f"Unauthorized attempt {attempts[ip]['count']}/{self.max_attempts}: {ip}")
        return False  # Not blocked yet
    
    def get_attempts_left(self, ip):
        """Get remaining attempts for IP"""
        attempts = self.load_attempts()
        if ip in attempts:
            return max(0, self.max_attempts - attempts[ip]['count'])
        return self.max_attempts
    
    def log_access_attempt(self, ip, status='blocked'):
        """Log access attempt (simplified)"""
        if status == 'blocked':
            logging.warning(f"Blocked IP access attempt: {ip} - Path: {request.path}")
        elif status == 'unauthorized':
            logging.warning(f"Unauthorized IP access attempt: {ip} - Path: {request.path}")
        else:
            logging.info(f"Allowed IP access: {ip} - Path: {request.path}")
    
    def check_ip_access(self):
        """Main IP checking function with attempt counter"""
        ip = self.get_client_ip()
        g.client_ip = ip
        
        # First check whitelist - if in whitelist, always allow
        if self.is_ip_allowed(ip):
            self.log_access_attempt(ip, 'allowed')
            return True, "allowed"
        
        # Then check blacklist - if blocked, ignore completely
        if self.is_ip_blocked(ip):
            self.log_access_attempt(ip, 'blocked')
            return False, "blocked"
        
        # If not in whitelist and not blocked, count attempts
        blocked = self.record_attempt(ip)
        if blocked:
            return False, "blocked"
        else:
            return False, "unauthorized"

ip_filter = IPFilter()

def require_ip_whitelist(f):
    """Decorator to check IP whitelist with attempt counter"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed, status = ip_filter.check_ip_access()
        
        if not allowed:
            if status == "blocked":
                return render_template("blocked.html",
                                     message="Ваш IP адрес заблокирован за превышение лимита попыток доступа.",
                                     ip=g.client_ip), 403
            else:
                return render_template("blocked.html",
                                     message="Доступ запрещен. Ваш IP адрес не в белом списке.",
                                     ip=g.client_ip), 403
        
        return f(*args, **kwargs)
    return decorated_function
                
                # Show error page for unauthorized IPs with attempts left
                attempts_left = ip_filter.get_attempts_left(g.client_ip)
                return render_template("blocked.html", 
                                     ip=g.client_ip,
                                     attempts_left=attempts_left), 403
        
        return f(*args, **kwargs)
    return decorated_function
