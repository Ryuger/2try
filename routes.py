from flask import session, render_template, request, redirect, url_for, flash, jsonify
from app import app, db
from auth import auth_manager, login_required, admin_required, superadmin_required, get_current_user
from ip_filter import require_ip_whitelist, ip_filter
from monitoring import *
from models import User, AccessLog, IPAttempt
import json
import os

# Make session permanent
@app.before_request
def make_session_permanent():
    session.permanent = True

# Маршруты аутентификации
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Заполните все поля', 'error')
            return render_template('login.html')

        success, user_data = auth_manager.authenticate_user(username, password)

        if success:
            session['user_id'] = user_data['user_id']
            session['username'] = user_data['username']
            session['role'] = user_data['role']

            flash(f'Добро пожаловать, {user_data["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверные учетные данные', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Выход из системы"""
    username = session.get('username', 'Пользователь')
    session.clear()
    flash(f'До свидания, {username}!', 'info')
    return redirect(url_for('login'))

@app.route('/')
@require_ip_whitelist
@login_required
def index():
    """Главная страница - показывает dashboard"""
    current_user = get_current_user()

    # Получение данных для мониторинга
    groups = get_groups()
    selected_group = request.args.get('group', groups[0] if groups else None)
    selected_subgroup = request.args.get('subgroup', 'Все')
    subgroups = get_subgroups(selected_group) if selected_group else ['Все']

    hosts = get_hosts(selected_group, selected_subgroup) if selected_group else []
    selected_host = request.args.get('host', hosts[0]['address'] if hosts else None)

    start_time = request.args.get('start_time', None)
    end_time = request.args.get('end_time', None)
    status = request.args.get('status', None)
    ping_history = get_ping_history(selected_group, selected_host, start_time, end_time, status, selected_subgroup) if selected_group and selected_host else []

    dashboard_data = get_dashboard_data(selected_group, selected_subgroup) if selected_group else {'availability': [], 'latency': [], 'down': []}

    # Получение статусов подгрупп для цветового кодирования
    subgroup_statuses = {}
    if selected_group:
        for sg in subgroups:
            if sg != 'Все':
                subgroup_statuses[sg] = get_subgroup_status_summary(selected_group, sg)

    # Получение статусов хостов
    host_statuses = {}
    if selected_group:
        for host in hosts:
            host_statuses[host['address']] = get_host_status_color(selected_group, host['address'])

    return render_template('index.html', 
                         groups=groups, 
                         selected_group=selected_group, 
                         subgroups=subgroups, 
                         selected_subgroup=selected_subgroup, 
                         hosts=hosts, 
                         selected_host=selected_host, 
                         ping_history=ping_history, 
                         dashboard_data=dashboard_data,
                         start_time=start_time,
                         end_time=end_time,
                         status=status,
                         subgroup_statuses=subgroup_statuses,
                         host_statuses=host_statuses,
                         user=current_user)

@app.route('/admin')
@require_ip_whitelist
@admin_required
def admin():
    """Административная панель"""
    current_user = get_current_user()

    # Получение логов доступа (из БД если есть)
    access_logs = []
    try:
        access_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(100).all()
    except:
        pass

    # Получение заблокированных IP из JSON файлов
    blacklist = ip_filter.load_blacklist()
    attempts = ip_filter.load_attempts()

    # Создание списка заблокированных IP с информацией о попытках
    blocked_ips = []
    for ip in blacklist:
        ip_attempts = attempts.get(ip, {})
        blocked_ips.append({
            'ip_address': ip,
            'attempt_count': ip_attempts.get('count', 0),
            'first_attempt': ip_attempts.get('first_attempt', ''),
            'last_attempt': ip_attempts.get('last_attempt', '')
        })

    # Загрузка белого списка
    whitelist = ip_filter.load_whitelist()

    return render_template('admin.html',
                         access_logs=access_logs,
                         blocked_ips=blocked_ips,
                         whitelist=whitelist,
                         blacklist=blacklist,
                         user=current_user)

@app.route('/admin/whitelist', methods=['POST'])
@require_ip_whitelist
@login_required
def update_whitelist():
    """Обновление белого списка IP"""
    current_user = get_current_user()
    if not current_user or current_user['role'] not in ['admin', 'superadmin']:
        return jsonify({'error': 'Нет прав доступа'}), 403

    action = request.form.get('action')
    ip = request.form.get('ip', '').strip()

    if not ip:
        flash('IP адрес не может быть пустым', 'error')
        return redirect(url_for('admin'))

    whitelist = ip_filter.load_whitelist()

    if action == 'add' and ip not in whitelist:
        whitelist.append(ip)
        try:
            os.makedirs(os.path.dirname(ip_filter.whitelist_file), exist_ok=True)
            with open(ip_filter.whitelist_file, 'w') as f:
                json.dump({'allowed_ips': whitelist}, f, indent=2)
            flash(f'IP {ip} добавлен в белый список', 'success')
        except Exception as e:
            flash(f'Ошибка сохранения: {e}', 'error')

    elif action == 'remove' and ip in whitelist:
        whitelist.remove(ip)
        try:
            with open(ip_filter.whitelist_file, 'w') as f:
                json.dump({'allowed_ips': whitelist}, f, indent=2)
            flash(f'IP {ip} удален из белого списка', 'success')
        except Exception as e:
            flash(f'Ошибка сохранения: {e}', 'error')

    return redirect(url_for('admin'))

@app.route('/admin/unblock', methods=['POST'])
@require_ip_whitelist
@login_required
def unblock_ip():
    """Разблокировка IP адреса"""
    current_user = get_current_user()
    if not current_user or current_user['role'] not in ['admin', 'superadmin']:
        return jsonify({'error': 'Нет прав доступа'}), 403

    ip = request.form.get('ip', '').strip()
    if not ip:
        flash('IP адрес не может быть пустым', 'error')
        return redirect(url_for('admin'))

    # Удаление из базы данных (если есть)
    try:
        attempt = IPAttempt.query.filter_by(ip_address=ip).first()
        if attempt:
            db.session.delete(attempt)
            db.session.commit()
    except:
        pass

    # Удаление из файла черного списка
    blacklist = ip_filter.load_blacklist()
    if ip in blacklist:
        blacklist.remove(ip)
        ip_filter.save_blacklist(blacklist)

    # Удаление из счетчика попыток
    attempts = ip_filter.load_attempts()
    if ip in attempts:
        del attempts[ip]
        ip_filter.save_attempts(attempts)

    flash(f'IP {ip} разблокирован', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/users')
@require_ip_whitelist
@admin_required
def manage_users():
    """Управление пользователями"""
    current_user = get_current_user()
    users = auth_manager.get_all_users()
    return render_template('admin_users.html', users=users, user=current_user)

@app.route('/admin/users/create', methods=['POST'])
@require_ip_whitelist
@admin_required
def create_user():
    """Создание пользователя"""
    current_user = get_current_user()

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'user')

    # Только суперадмин может создавать администраторов
    if role == 'admin' and current_user['role'] != 'superadmin':
        flash('Недостаточно прав для создания администратора', 'error')
        return redirect(url_for('manage_users'))

    if not username or not password:
        flash('Заполните все обязательные поля', 'error')
        return redirect(url_for('manage_users'))

    success, message = auth_manager.create_user(
        username=username,
        password=password,
        role=role,
        created_by=current_user['user_id']
    )

    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')

    return redirect(url_for('manage_users'))

@app.route('/admin/users/<user_id>/reset_password', methods=['POST'])
@require_ip_whitelist
@admin_required
def reset_user_password():
    """Сброс пароля пользователя"""
    current_user = get_current_user()
    user_id = request.view_args['user_id']
    new_password = request.form.get('new_password', '')

    if not new_password:
        flash('Укажите новый пароль', 'error')
        return redirect(url_for('manage_users'))

    target_user = auth_manager.get_user_by_id(user_id)
    if not target_user:
        flash('Пользователь не найден', 'error')
        return redirect(url_for('manage_users'))

    # Проверка прав
    if (target_user['role'] in ['admin', 'superadmin'] and 
        current_user['role'] != 'superadmin'):
        flash('Недостаточно прав для сброса пароля администратора', 'error')
        return redirect(url_for('manage_users'))

    success, message = auth_manager.update_user(user_id, password=new_password)

    if success:
        flash(f'Пароль пользователя {target_user["username"]} сброшен', 'success')
    else:
        flash(message, 'error')

    return redirect(url_for('manage_users'))

@app.route('/admin/users/<user_id>/toggle_admin', methods=['POST'])
@require_ip_whitelist
@admin_required
def toggle_admin(user_id):
    """Переключение статуса администратора пользователя"""
    current_user = get_current_user()
    if not current_user or current_user['role'] != 'superadmin':
        return jsonify({'error': 'Нет прав доступа'}), 403

    target_user = auth_manager.get_user_by_id(user_id)
    if target_user and target_user['user_id'] != current_user['user_id']:
        new_role = 'admin' if target_user['role'] == 'user' else 'user'
        success, message = auth_manager.update_user(user_id, role=new_role)

        if success:
            status = 'назначен' if new_role == 'admin' else 'снят'
            flash(f'Пользователь {target_user["username"]} {status} администратором', 'success')
        else:
            flash(message, 'error')

    return redirect(url_for('manage_users'))

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

# API endpoints for AJAX requests  
@app.route('/api/groups')
@login_required
def api_groups():
    """API endpoint для получения списка групп"""
    groups = get_groups()
    return jsonify({'groups': groups})

@app.route('/api/subgroups')
@login_required
def api_subgroups():
    """API endpoint для получения подгрупп"""
    group_name = request.args.get('group')
    if not group_name:
        return jsonify({'error': 'Group parameter required'}), 400

    subgroups = get_subgroups(group_name)
    subgroup_statuses = {}

    for sg in subgroups:
        if sg != 'Все':
            subgroup_statuses[sg] = get_subgroup_status_summary(group_name, sg)

    return jsonify({
        'subgroups': subgroups,
        'subgroup_statuses': subgroup_statuses
    })

@app.route('/api/hosts')
@login_required
def api_hosts():
    """API endpoint для получения хостов"""
    group_name = request.args.get('group')
    subgroup = request.args.get('subgroup', 'Все')

    if not group_name:
        return jsonify({'error': 'Group parameter required'}), 400

    hosts = get_hosts(group_name, subgroup)
    host_statuses = {}

    for host in hosts:
        host_statuses[host['address']] = get_host_status_color(group_name, host['address'])

    return jsonify({
        'hosts': hosts,
        'host_statuses': host_statuses
    })

@app.route('/api/ping_history')
@login_required
def api_ping_history():
    """API endpoint для получения истории пингов"""
    group_name = request.args.get('group')
    address = request.args.get('host')
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    status = request.args.get('status')
    subgroup = request.args.get('subgroup')

    if not group_name or not address:
        return jsonify({'error': 'Group and host parameters required'}), 400

    ping_history = get_ping_history(group_name, address, start_time, end_time, status, subgroup)

    return jsonify({'ping_history': ping_history})

@app.route('/api/dashboard')
@login_required
def api_dashboard():
    """API endpoint для получения данных дашборда"""
    group_name = request.args.get('group')
    subgroup = request.args.get('subgroup', 'Все')

    if not group_name:
        return jsonify({'error': 'Group parameter required'}), 400

    dashboard_data = get_dashboard_data(group_name, subgroup)

    return jsonify({'dashboard_data': dashboard_data})

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500