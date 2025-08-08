// Современная система мониторинга с AJAX поддержкой

class MonitoringDashboard {
    constructor() {
        this.charts = {};
        this.updateInterval = 300000; // 5 минут
        this.currentState = {
            group: null,
            subgroup: 'Все',
            host: null,
            tab: 'hosts'
        };
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadInitialData();
        this.startAutoRefresh();
        this.initializeFeatherIcons();
    }

    setupEventListeners() {
        // Обработка изменения группы
        const groupSelect = document.getElementById('group');
        if (groupSelect) {
            groupSelect.addEventListener('change', this.handleGroupChange.bind(this));
            this.currentState.group = groupSelect.value;
        }

        // Обработка вкладок
        this.setupTabs();

        // Фильтрация истории
        const filterBtn = document.querySelector('.filter-history-btn');
        if (filterBtn) {
            filterBtn.addEventListener('click', this.handleFilterHistory.bind(this));
        }

        // Делегированные обработчики для динамически создаваемых элементов
        document.addEventListener('click', this.handleDelegatedClicks.bind(this));
        document.addEventListener('change', this.handleDelegatedChanges.bind(this));
    }

    handleDelegatedClicks(event) {
        // Обработка кликов по подгруппам
        if (event.target.matches('.subgroup-tab')) {
            event.preventDefault();
            const subgroup = event.target.dataset.subgroup;
            this.handleSubgroupChange(subgroup);
        }

        // Обработка кликов по хостам для перехода к логам
        if (event.target.matches('.host-row td') || event.target.closest('.host-row')) {
            const row = event.target.closest('.host-row');
            if (row) {
                const hostAddress = row.querySelector('.fw-bold').textContent;
                this.drillDownToHostLogs(hostAddress);
            }
        }
    }

    handleDelegatedChanges(event) {
        // Обработка изменения хоста в истории пингов
        if (event.target.matches('#host')) {
            this.currentState.host = event.target.value;
            this.loadPingHistory();
        }
    }

    setupTabs() {
        const tabLinks = document.querySelectorAll('.tab-link');
        tabLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const tabName = link.getAttribute('href').substring(1);
                this.switchTab(tabName);
            });
        });

        // Открыть первую вкладку по умолчанию
        if (tabLinks.length > 0) {
            this.switchTab('hosts');
        }
    }

    switchTab(tabName) {
        this.currentState.tab = tabName;

        // Обновить активную вкладку в UI
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });

        document.querySelectorAll('.tab-link').forEach(link => {
            link.classList.remove('active');
        });

        const activeTab = document.getElementById(tabName);
        if (activeTab) {
            activeTab.classList.add('active');
        }

        const activeLink = document.querySelector(`a[href="#${tabName}"]`);
        if (activeLink) {
            activeLink.classList.add('active');
        }

        // Загрузить данные для выбранной вкладки
        this.loadTabData(tabName);
    }

    async loadTabData(tabName) {
        try {
            switch (tabName) {
                case 'hosts':
                    await this.loadHosts();
                    break;
                case 'history':
                    await this.loadPingHistory();
                    break;
                case 'dashboard':
                    await this.loadDashboard();
                    break;
            }
        } catch (error) {
            this.handleError(error);
        }
    }

    async loadInitialData() {
        try {
            await this.loadGroups();
            if (this.currentState.group) {
                await this.loadSubgroups();
                await this.loadTabData(this.currentState.tab);
                this.updatePageHeaders(); // Обновление заголовков после загрузки данных
            }
        } catch (error) {
            this.handleError(error);
        }
    }

    async loadGroups() {
        try {
            const response = await fetch('/api/groups');
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            // Если группа не выбрана, выбрать первую
            if (!this.currentState.group && data.groups.length > 0) {
                this.currentState.group = data.groups[0];
                const groupSelect = document.getElementById('group');
                if (groupSelect) {
                    groupSelect.value = this.currentState.group;
                }
            }
        } catch (error) {
            this.handleError(error);
        }
    }

    async handleGroupChange() {
        const groupSelect = document.getElementById('group');
        this.currentState.group = groupSelect.value;
        this.currentState.subgroup = 'Все';
        this.currentState.host = null;

        if (this.currentState.group) {
            await this.loadSubgroups();
            await this.loadTabData(this.currentState.tab);
            this.updatePageHeaders(); // Обновление заголовков при смене группы
        }
    }

    async loadSubgroups() {
        if (!this.currentState.group) return;

        try {
            const response = await fetch(`/api/subgroups?group=${encodeURIComponent(this.currentState.group)}`);
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            this.renderSubgroups(data.subgroups, data.subgroup_statuses);
        } catch (error) {
            this.handleError(error);
        }
    }

    renderSubgroups(subgroups, subgroupStatuses) {
        const container = document.querySelector('.subgroup-tabs');
        if (!container) return;

        container.innerHTML = '';

        subgroups.forEach(subgroup => {
            const statusInfo = subgroupStatuses[subgroup] || {};
            const statusClass = statusInfo.status || 'secondary';

            const tab = document.createElement('a');
            tab.href = '#';
            tab.className = `subgroup-tab status-${statusClass}${subgroup === this.currentState.subgroup ? ' active' : ''}`;
            tab.dataset.subgroup = subgroup;

            tab.innerHTML = `
                <span class="status-indicator status-${statusClass}"></span>
                ${subgroup}
                ${subgroup !== 'Все' && statusInfo.up !== undefined ?
                    `<small class="text-muted">(${statusInfo.up}/${statusInfo.total})</small>` : ''}
            `;

            container.appendChild(tab);
        });
    }

    async handleSubgroupChange(subgroup) {
        this.currentState.subgroup = subgroup;

        // Обновить активную подгруппу в UI
        document.querySelectorAll('.subgroup-tab').forEach(tab => {
            tab.classList.remove('active');
        });

        const activeTab = document.querySelector(`[data-subgroup="${subgroup}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
        }

        await this.loadTabData(this.currentState.tab);
    }

    async loadHosts() {
        if (!this.currentState.group) return;

        try {
            this.showLoadingIndicator('hosts');

            const response = await fetch(`/api/hosts?group=${encodeURIComponent(this.currentState.group)}&subgroup=${encodeURIComponent(this.currentState.subgroup)}`);
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            this.renderHosts(data.hosts, data.host_statuses);
            this.updateHostSelector(data.hosts); // Обновление селектора хостов
        } catch (error) {
            this.handleError(error);
        } finally {
            this.hideLoadingIndicator('hosts');
        }
    }

    renderHosts(hosts, hostStatuses) {
        const tableBody = document.querySelector('#hosts tbody');
        if (!tableBody) return;

        if (hosts.length === 0) {
            const container = document.getElementById('hosts');
            container.innerHTML = `
                <div class="dashboard-card">
                    <div class="alert alert-info">
                        <i data-feather="info"></i>
                        Список хостов пуст или группа не существует.
                    </div>
                </div>
            `;
            feather.replace();
            return;
        }

        let html = '';
        hosts.forEach(host => {
            const statusClass = hostStatuses[host.address] || 'secondary';
            html += `
                <tr class="host-row status-${statusClass}" style="cursor: pointer;" title="Нажмите для просмотра логов">
                    <td>
                        <span class="status-indicator status-${statusClass}"></span>
                    </td>
                    <td class="fw-bold">${host.address}</td>
                    <td>${host.description}</td>
                    <td>
                        <span class="badge bg-secondary">${host.subgroup}</span>
                    </td>
                </tr>
            `;
        });

        tableBody.innerHTML = html;
    }

    async drillDownToHostLogs(hostAddress) {
        this.currentState.host = hostAddress;

        // Переключиться на вкладку истории
        this.switchTab('history');

        // Подождать, пока вкладка загрузится, затем установить хост
        setTimeout(() => {
            const hostSelect = document.getElementById('host');
            if (hostSelect) {
                hostSelect.value = hostAddress;
                this.loadPingHistory();
            }
        }, 100);
    }

    async loadPingHistory() {
        if (!this.currentState.group || !this.currentState.host) {
            this.renderEmptyHistory();
            return;
        }

        try {
            this.showLoadingIndicator('history');

            const startTime = document.getElementById('start_time')?.value || '';
            const endTime = document.getElementById('end_time')?.value || '';
            const status = document.getElementById('status')?.value || '';

            const params = new URLSearchParams({
                group: this.currentState.group,
                host: this.currentState.host,
                subgroup: this.currentState.subgroup
            });

            if (startTime) params.set('start_time', startTime);
            if (endTime) params.set('end_time', endTime);
            if (status) params.set('status', status);

            const response = await fetch(`/api/ping_history?${params}`);
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            this.renderPingHistory(data.ping_history);
        } catch (error) {
            this.handleError(error);
        } finally {
            this.hideLoadingIndicator('history');
        }
    }

    renderPingHistory(pingHistory) {
        const tableBody = document.querySelector('#history tbody');
        if (!tableBody) return;

        if (pingHistory.length === 0) {
            this.renderEmptyHistory();
            return;
        }

        let html = '';
        pingHistory.forEach(entry => {
            const badgeClass = entry.status === 'Доступен' ? 'success' : 'danger';
            html += `
                <tr>
                    <td>${entry.timestamp}</td>
                    <td>
                        <span class="badge bg-${badgeClass}">
                            ${entry.status}
                        </span>
                    </td>
                    <td>${entry.latency}</td>
                </tr>
            `;
        });

        tableBody.innerHTML = html;
    }

    renderEmptyHistory() {
        const container = document.getElementById('history');
        const existingTable = container.querySelector('.table-responsive');
        if (existingTable) {
            existingTable.innerHTML = `
                <div class="alert alert-info">
                    <i data-feather="info"></i>
                    История пингов пуста или хост не выбран.
                </div>
            `;
            feather.replace();
        }
    }

    async handleFilterHistory() {
        await this.loadPingHistory();
    }

    async loadDashboard() {
        if (!this.currentState.group) return;

        try {
            this.showLoadingIndicator('dashboard');

            const response = await fetch(`/api/dashboard?group=${encodeURIComponent(this.currentState.group)}&subgroup=${encodeURIComponent(this.currentState.subgroup)}`);
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            window.dashboardData = data.dashboard_data;
            this.initializeCharts();
        } catch (error) {
            this.handleError(error);
        } finally {
            this.hideLoadingIndicator('dashboard');
        }
    }

    initializeCharts() {
        // Уничтожить существующие графики
        Object.values(this.charts).forEach(chart => {
            if (chart) {
                chart.destroy();
            }
        });
        this.charts = {};

        // График доступности
        const availabilityCanvas = document.getElementById('availabilityChart');
        if (availabilityCanvas && window.dashboardData) {
            this.createAvailabilityChart(availabilityCanvas);
        }

        // График задержки
        const latencyCanvas = document.getElementById('latencyChart');
        if (latencyCanvas && window.dashboardData) {
            this.createLatencyChart(latencyCanvas);
        }

        // График недоступных хостов
        const downCanvas = document.getElementById('downChart');
        if (downCanvas && window.dashboardData) {
            this.createDownChart(downCanvas);
        }
    }

    createAvailabilityChart(canvas) {
        const data = window.dashboardData.availability || [];

        this.charts.availability = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: data.map(item => item.address),
                datasets: [{
                    label: 'Доступность (%)',
                    data: data.map(item => item.availability),
                    backgroundColor: data.map(item => this.getAvailabilityColor(item.availability)),
                    borderColor: data.map(item => this.getAvailabilityColor(item.availability, true)),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `Доступность: ${context.parsed.y}%`;
                            }
                        }
                    }
                }
            }
        });
    }

    createLatencyChart(canvas) {
        const data = window.dashboardData.latency || [];

        this.charts.latency = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: data.map(item => item.address),
                datasets: [{
                    label: 'Средняя задержка (сек)',
                    data: data.map(item => item.avg_latency),
                    backgroundColor: 'rgba(153, 102, 255, 0.6)',
                    borderColor: 'rgba(153, 102, 255, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return value + 's';
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `Задержка: ${context.parsed.y}s`;
                            }
                        }
                    }
                }
            }
        });
    }

    createDownChart(canvas) {
        const data = window.dashboardData.down || [];

        this.charts.down = new Chart(canvas, {
            type: 'line',
            data: {
                labels: data.map(item => item.timestamp),
                datasets: [{
                    label: 'Недоступные хосты',
                    data: data.map(item => item.down_count),
                    fill: false,
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.1,
                    pointBackgroundColor: 'rgba(255, 99, 132, 1)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: 'rgba(255, 99, 132, 1)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    },
                    x: {
                        ticks: {
                            maxTicksLimit: 12
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                }
            }
        });
    }

    getAvailabilityColor(availability, border = false) {
        const alpha = border ? 1 : 0.6;
        if (availability >= 95) {
            return `rgba(25, 135, 84, ${alpha})`; // green
        } else if (availability >= 80) {
            return `rgba(255, 193, 7, ${alpha})`; // yellow
        } else {
            return `rgba(220, 53, 69, ${alpha})`; // red
        }
    }

    startAutoRefresh() {
        // Автоматическое обновление каждые 5 минут
        setInterval(() => {
            this.refreshCurrentTab();
        }, this.updateInterval);
    }

    async refreshCurrentTab() {
        try {
            await this.loadTabData(this.currentState.tab);
        } catch (error) {
            this.handleError(error);
        }
    }

    initHostList() {
        // Убираем системную полосу прокрутки и добавляем кастомную обработку
        const hostLists = document.querySelectorAll('.host-list');
        hostLists.forEach(hostList => {
            // Убираем все системные полосы прокрутки
            hostList.style.scrollbarWidth = 'none'; // Firefox
            hostList.style.msOverflowStyle = 'none'; // IE и Edge

            // Добавляем обработчик для Chrome/Safari/Opera
            const style = document.createElement('style');
            style.innerHTML = `
                .host-list::-webkit-scrollbar {
                    display: none !important;
                }
                .host-item {
                    transition: none !important;
                    padding: 8px 12px;
                    margin-bottom: 1px;
                    cursor: pointer;
                }
                .host-item:hover {
                    background-color: #f8f9fa !important;
                }
            `;
            document.head.appendChild(style);
        });
    }

    showLoadingIndicator(tabName) {
        const tab = document.getElementById(tabName);
        if (tab) {
            const existing = tab.querySelector('.loading-indicator');
            if (existing) existing.remove();

            const indicator = document.createElement('div');
            indicator.className = 'loading-indicator';
            indicator.innerHTML = `
                <div class="alert alert-info d-flex align-items-center">
                    <div class="spinner-border spinner-border-sm me-2" role="status">
                        <span class="visually-hidden">Загрузка...</span>
                    </div>
                    Обновление данных...
                </div>
            `;

            tab.insertBefore(indicator, tab.firstChild);
        }
    }

    hideLoadingIndicator(tabName) {
        const tab = document.getElementById(tabName);
        if (tab) {
            const indicator = tab.querySelector('.loading-indicator');
            if (indicator) {
                indicator.remove();
            }
        }
    }

    initializeFeatherIcons() {
        if (typeof feather !== 'undefined') {
            feather.replace();
        }
    }

    updatePageHeaders() {
        // Обновить заголовок группы в зависимости от активной вкладки
        const groupTitle = document.querySelector('h2:contains("Список хостов в группе")');
        if (groupTitle) {
            groupTitle.textContent = `Список хостов в группе '${this.currentState.group}'`;
        }

        // Найти и обновить все заголовки с названием группы
        const titleElements = document.querySelectorAll('h2, h3, .card-title');
        titleElements.forEach(element => {
            if (element.textContent.includes('Список хостов в группе')) {
                element.innerHTML = `<i data-feather="server"></i> Список хостов в группе '${this.currentState.group}'`;
            }
            if (element.textContent.includes('История пингов для группы')) {
                element.innerHTML = `<i data-feather="activity"></i> История пингов для группы '${this.currentState.group}'`;
            }
            if (element.textContent.includes('Дашборд группы')) {
                element.innerHTML = `<i data-feather="bar-chart-2"></i> Дашборд группы '${this.currentState.group}'`;
            }
        });

        // Обновить иконки
        this.initializeFeatherIcons();
    }

    updateHostSelector(hosts) {
        const hostSelect = document.getElementById('host');
        if (!hostSelect) return;

        // Очистить селектор
        hostSelect.innerHTML = '<option value="">Выберите хост</option>';

        // Добавить новые опции
        hosts.forEach(host => {
            const option = document.createElement('option');
            option.value = host.address;
            option.textContent = `${host.address} - ${host.description}`;

            // Выбрать текущий хост если он есть
            if (host.address === this.currentState.host) {
                option.selected = true;
            }

            hostSelect.appendChild(option);
        });

        // Если текущий хост не найден в новом списке, сбросить
        if (this.currentState.host && !hosts.find(h => h.address === this.currentState.host)) {
            this.currentState.host = null;
            hostSelect.value = '';
        }
    }

    // Утилиты для форматирования
    formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString('ru-RU');
    }

    formatLatency(latency) {
        if (latency === null || latency === undefined) {
            return 'N/A';
        }
        return `${latency}ms`;
    }

    // Обработка ошибок
    handleError(error) {
        console.error('Monitoring Dashboard Error:', error);

        // Удалить предыдущие ошибки
        const existingErrors = document.querySelectorAll('.error-alert');
        existingErrors.forEach(alert => alert.remove());

        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger alert-dismissible fade show error-alert';
        alertDiv.innerHTML = `
            <strong>Ошибка:</strong> ${error.message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        const container = document.querySelector('.container');
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
        }
    }
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    window.monitoringDashboard = new MonitoringDashboard();
});

// Экспорт для использования в других модулях (только в Node.js окружении)
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
    module.exports = MonitoringDashboard;
}