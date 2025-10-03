const loginView = document.getElementById('login-view');
const appView = document.getElementById('app-view');
const loginForm = document.getElementById('login-form');
const loginFeedback = document.getElementById('login-feedback');
const sessionInfo = document.getElementById('session-info');
const toastContainer = document.getElementById('toast-container');
const logoutBtn = document.getElementById('logout-btn');
const refreshAllBtn = document.getElementById('refresh-all');
const routerVendorSelect = document.getElementById('router-vendor');
const routerForm = document.getElementById('router-form');
const snmpTestForm = document.getElementById('snmp-test-form');
const snmpTestResult = document.getElementById('snmp-test-result');
const routersTable = document.querySelector('#routers-table tbody');
const alertsTable = document.querySelector('#alerts-table tbody');
const alertForm = document.getElementById('alert-form');
const configView = document.getElementById('config-view');
const configEditor = document.getElementById('config-editor');
const configFeedback = document.getElementById('config-feedback');
const whitelistView = document.getElementById('whitelist-view');
const whitelistEditor = document.getElementById('whitelist-editor');
const whitelistFeedback = document.getElementById('whitelist-feedback');
const firewallStatus = document.getElementById('firewall-status');
const grafanaList = document.getElementById('grafana-list');
const bgpTable = document.querySelector('#bgp-table tbody');
const interfacesTable = document.querySelector('#interfaces-table tbody');
const flowsTable = document.querySelector('#flows-table tbody');
const flowLimitInput = document.getElementById('flow-limit');
const systemCards = document.getElementById('system-cards');
const statsOverview = document.getElementById('stats-overview');
const topSourcesTable = document.querySelector('#top-sources-table tbody');
const topAppsTable = document.querySelector('#top-apps-table tbody');

function showToast(message, variant = 'info') {
    const wrapper = document.createElement('div');
    wrapper.className = `toast text-bg-${variant}`;
    wrapper.setAttribute('role', 'alert');
    wrapper.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    toastContainer.appendChild(wrapper);
    const toast = new bootstrap.Toast(wrapper, { delay: 4000 });
    toast.show();
    wrapper.addEventListener('hidden.bs.toast', () => wrapper.remove());
}

async function apiFetch(path, options = {}) {
    const opts = { method: 'GET', credentials: 'include', ...options };
    opts.headers = { Accept: 'application/json', ...(options.headers || {}) };
    if (options.json !== undefined) {
        opts.body = JSON.stringify(options.json);
        opts.headers['Content-Type'] = 'application/json';
    }
    const response = await fetch(path, opts);
    if (!response.ok) {
        let detail = '';
        try {
            const data = await response.json();
            detail = data.error || JSON.stringify(data);
        } catch (_) {
            detail = await response.text();
        }
        throw new Error(detail || response.statusText);
    }
    if (response.status === 204) {
        return null;
    }
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        return response.json();
    }
    return response.text();
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return '-';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }
    return `${value.toFixed(value >= 10 || value % 1 === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatPercent(value, fractionDigits = 1) {
    if (!Number.isFinite(value)) return '-';
    return `${value.toFixed(fractionDigits)}%`;
}

function formatNumber(value) {
    if (!Number.isFinite(value)) return '-';
    return value.toLocaleString('pt-BR');
}

function formatDate(value) {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString('pt-BR');
}

function showLogin(message) {
    if (message) {
        loginFeedback.textContent = message;
        loginFeedback.classList.add('text-danger');
    } else {
        loginFeedback.textContent = '';
        loginFeedback.classList.remove('text-danger');
    }
    loginView.classList.remove('d-none');
    appView.classList.add('d-none');
}

function showApp() {
    loginView.classList.add('d-none');
    appView.classList.remove('d-none');
}

async function checkSession() {
    try {
        const data = await apiFetch('/api/session');
        sessionCache = data;
        renderSession();
        showApp();
        await Promise.all([
            loadVendors(),
            loadDashboard(),
            loadConfig(),
            loadWhitelist(),
            loadFirewallStatus(),
            loadGrafana(),
        ]);
    } catch (error) {
        sessionCache = null;
        showLogin(error.message.includes('token') ? 'Sessão expirada, realize login novamente.' : 'Autentique-se para continuar.');
    }
}

function renderSession() {
    if (!sessionCache) return;
    const expires = sessionCache.expires_at ? formatDate(sessionCache.expires_at) : 'Sessão ativa';
    sessionInfo.textContent = `Usuário: ${sessionCache.user} • Iniciado: ${formatDate(sessionCache.started_at)} • Expira: ${expires}`;
}

loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const user = document.getElementById('login-user').value.trim();
    const pass = document.getElementById('login-pass').value;
    if (!user || !pass) {
        loginFeedback.textContent = 'Informe usuário e senha.';
        loginFeedback.classList.add('text-danger');
        return;
    }
    loginFeedback.textContent = 'Autenticando...';
    loginFeedback.classList.remove('text-danger');
    try {
        await apiFetch('/api/login', { method: 'POST', json: { user, pass } });
        loginFeedback.textContent = '';
        showToast('Login realizado com sucesso.', 'success');
        await checkSession();
    } catch (error) {
        loginFeedback.textContent = error.message || 'Falha ao autenticar';
        loginFeedback.classList.add('text-danger');
    }
});

logoutBtn.addEventListener('click', async () => {
    try {
        await apiFetch('/api/logout', { method: 'POST' });
    } catch (_) {
        // ignore
    }
    sessionCache = null;
    showLogin('Sessão finalizada.');
});

refreshAllBtn.addEventListener('click', async () => {
            loadConfig(),
            loadWhitelist(),
            loadFirewallStatus(),
            loadGrafana(),
            loadBGPPeers(),
            loadInterfaces(),
            loadFlows(),
        ]);
    }
});

async function loadVendors() {
    try {
        vendorsCache = await apiFetch('/api/vendors');
        routerVendorSelect.innerHTML = vendorsCache.map((vendor) => `<option value="${vendor}">${vendor}</option>`).join('');
    } catch (error) {
        showToast(`Falha ao carregar vendors: ${error.message}`, 'danger');
    }
}

async function loadDashboard() {
    await Promise.all([loadSystemStatus(), loadStats(), loadDashboardStats()]);
}

async function loadSystemStatus() {
    try {
        const data = await apiFetch('/api/system');
        renderSystemCards(data);
    } catch (error) {
        showToast(`Erro ao buscar status do sistema: ${error.message}`, 'danger');
    }
}

function renderSystemCards(data) {
    if (!data) return;
    const cards = [];
    cards.push({
        title: 'Uso de CPU',
        icon: 'microchip',
        value: formatPercent(data.cpu || 0),
        footer: `${data.cores?.length || 0} núcleos monitorados`,
    });
    cards.push({
        title: 'Memória',
        icon: 'memory',
        value: `${formatBytes((data.mem?.used_gb || 0) * 1024 ** 3)} / ${formatBytes((data.mem?.total_gb || 0) * 1024 ** 3)}`,
        footer: formatPercent(((data.mem?.used_gb || 0) / (data.mem?.total_gb || 1)) * 100),
    });
    cards.push({
        title: 'Armazenamento',
        icon: 'hard-drive',
        value: `${formatBytes((data.disk?.used_gb || 0) * 1024 ** 3)} / ${formatBytes((data.disk?.total_gb || 0) * 1024 ** 3)}`,
        footer: formatPercent(((data.disk?.used_gb || 0) / (data.disk?.total_gb || 1)) * 100),
    });
    cards.push({
        title: 'Uptime',
        icon: 'clock',
        value: data.host?.uptime || '-',
        footer: `Hardware ID: ${data.host?.hwid || '-'}`,
    });
    systemCards.innerHTML = cards
        .map(
            (card) => `
            <div class="col-md-6 col-xl-3">
                <div class="card h-100">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <span class="text-secondary">${card.title}</span>
                            <i class="fa-solid fa-${card.icon} text-primary"></i>
                        </div>
                        <p class="fs-4 fw-semibold mt-2">${card.value}</p>
                        <p class="text-secondary mb-0">${card.footer}</p>
                    </div>
                </div>
            </div>`
        )
        .join('');
}

async function loadStats() {
    try {
        const data = await apiFetch('/stats');
        const entries = {
            'Fluxos processados': formatNumber(data.flows_processed),
            'Erros de fluxo': formatNumber(data.flow_errors),
            'Erros SNMP': formatNumber(data.snmp_errors),
            'Fluxos ativos': formatNumber(data.active_flows),
            'Fila de processamento': formatNumber(data.queue_length),
            'Interfaces monitoradas': formatNumber(data.interface_count),
            'Goroutines': formatNumber(data.goroutines),
        };
        statsOverview.innerHTML = Object.entries(entries)
            .map(
                ([label, value]) => `
                <dt class="col-7">${label}</dt>
                <dd class="col-5 text-end fw-semibold">${value}</dd>`
            )
            .join('');
    } catch (error) {
        showToast(`Erro ao buscar estatísticas: ${error.message}`, 'danger');
    }
}

async function loadDashboardStats() {
    try {
        const data = await apiFetch('/api/dashboard/stats');
        const sourcesRows = (data.top_sources || [])
            .map(
                (item) => `
                <tr>
                    <td>${item.source_name}</td>
                    <td>${item.vendor || '-'}</td>
                    <td>${formatBytes(item.total_bytes)}</td>
                    <td>${formatPercent(item.percentage || 0)}</td>
                </tr>`
            )
            .join('');
        topSourcesTable.innerHTML = sourcesRows || '<tr><td colspan="4" class="text-center text-secondary">Nenhum dado.</td></tr>';

        const appsRows = (data.top_applications || [])
            .map(
                (item) => `
                <tr>
                    <td>${item.protocol}</td>
                    <td>${item.port}</td>
                    <td>${formatBytes(item.total_bytes)}</td>
                </tr>`
            )
            .join('');
        topAppsTable.innerHTML = appsRows || '<tr><td colspan="3" class="text-center text-secondary">Nenhum dado.</td></tr>';
    } catch (error) {
        showToast(`Erro ao buscar dados do dashboard: ${error.message}`, 'danger');
    }
}

async function loadRouters() {
    try {
        const routers = await apiFetch('/api/routers');
            .map((router) => {
                const snmp = router.snmp || {};
                return `
                <tr>
                    <td>${router.name}</td>
                    <td>${router.vendor}</td>
                    <td>${snmp.ip || '-'}</td>
                    <td>v${snmp.version || '-'} @ ${snmp.port || 161}</td>
                    <td class="text-nowrap">
                        <button class="btn btn-sm btn-outline-light me-1" data-action="edit-router" data-name="${encodeURIComponent(router.name)}">
                            <i class="fa-solid fa-pen"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" data-action="delete-router" data-name="${encodeURIComponent(router.name)}">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            })
            .join('');
      
routersTable.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    const name = decodeURIComponent(button.dataset.name || '');
    if (!name) return;

    if (action === 'delete-router') {
        if (!confirm(`Confirma remover o roteador ${name}?`)) return;
        try {
            await apiFetch(`/api/routers/${encodeURIComponent(name)}`, { method: 'DELETE' });
            showToast('Roteador removido.', 'success');
            await loadRouters();
        } catch (error) {
            showToast(`Falha ao remover: ${error.message}`, 'danger');
        }
    }

    if (action === 'edit-router') {
        try {
            const current = await apiFetch(`/api/routers/${encodeURIComponent(name)}`);
            const updatedText = prompt('Edite o JSON do roteador:', JSON.stringify(current, null, 2));
            if (!updatedText) return;
            const payload = JSON.parse(updatedText);
            await apiFetch(`/api/routers/${encodeURIComponent(name)}`, { method: 'PUT', json: payload });
            showToast('Roteador atualizado.', 'success');
            await loadRouters();
        } catch (error) {
            showToast(`Falha ao atualizar: ${error.message}`, 'danger');
        }
    }
});

routerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
        name: document.getElementById('router-name').value.trim(),
        vendor: document.getElementById('router-vendor').value,
        snmp: {
            ip: document.getElementById('router-ip').value.trim(),
            community: document.getElementById('router-community').value.trim() || 'public',
            port: Number(document.getElementById('router-port').value) || 161,
            version: document.getElementById('router-version').value,
        },
    };
    if (!payload.name || !payload.snmp.ip) {
        showToast('Informe nome e IP do roteador.', 'warning');
        return;
    }
    try {
        await apiFetch('/api/routers', { method: 'POST', json: payload });
        routerForm.reset();
        document.getElementById('router-community').value = 'public';
        document.getElementById('router-port').value = 161;
        showToast('Roteador cadastrado.', 'success');
        await loadRouters();
    } catch (error) {
        showToast(`Falha ao cadastrar: ${error.message}`, 'danger');
    }
});

snmpTestForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
        ip: document.getElementById('snmp-test-ip').value.trim(),
        community: document.getElementById('snmp-test-community').value.trim() || 'public',
        port: Number(document.getElementById('snmp-test-port').value) || 161,
        version: '2c',
    };
    snmpTestResult.textContent = 'Executando teste...';
    snmpTestResult.classList.remove('text-danger');
    try {
        const response = await apiFetch('/api/snmp/test', { method: 'POST', json: payload });
        snmpTestResult.textContent = `${response.message} (${response.description || 'sem descrição'})`;
    } catch (error) {
        snmpTestResult.textContent = error.message;
        snmpTestResult.classList.add('text-danger');
    }
});

async function loadAlerts() {
    try {
        const alerts = await apiFetch('/api/alerts');
            .map((rule) => `
                <tr>
                    <td>${rule.name}</td>
                    <td>${rule.enabled ? '<span class="badge bg-success">Ativo</span>' : '<span class="badge bg-secondary">Inativo</span>'}</td>
                    <td><code>${rule.filter || '-'}</code></td>
                    <td class="text-nowrap">
                        <button class="btn btn-sm btn-outline-light me-1" data-action="edit-alert" data-name="${encodeURIComponent(rule.name)}">
                            <i class="fa-solid fa-pen"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" data-action="delete-alert" data-name="${encodeURIComponent(rule.name)}">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </td>
                </tr>`)
            .join('');

alertsTable.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    const name = decodeURIComponent(button.dataset.name || '');
    if (!name) return;

    if (action === 'edit-alert') {
        try {
            const alerts = await apiFetch('/api/alerts');
            const current = alerts.find((item) => item.name === name);
            if (!current) {
                showToast('Regra não encontrada.', 'warning');
                return;
            }
            const updated = prompt('Atualize o JSON da regra:', JSON.stringify(current, null, 2));
            if (!updated) return;
            const payload = JSON.parse(updated);
            await apiFetch(`/api/alerts/${encodeURIComponent(name)}`, { method: 'PUT', json: payload });
            showToast('Regra atualizada.', 'success');
            await loadAlerts();
        } catch (error) {
            showToast(`Falha ao atualizar: ${error.message}`, 'danger');
        }
    }
});

alertForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
        name: document.getElementById('alert-name').value.trim(),
        filter: document.getElementById('alert-filter').value.trim(),
        condition: document.getElementById('alert-condition').value.trim(),
        time_window_seconds: Number(document.getElementById('alert-window').value) || 60,
        actions: document.getElementById('alert-actions').value.split(',').map((item) => item.trim()).filter(Boolean),
        comment: document.getElementById('alert-comment').value.trim(),
        enabled: document.getElementById('alert-enabled').checked,
    };
    try {
        await apiFetch('/api/alerts', { method: 'POST', json: payload });
        alertForm.reset();
        document.getElementById('alert-window').value = 60;
        document.getElementById('alert-enabled').checked = true;
        showToast('Regra criada com sucesso.', 'success');
        await loadAlerts();
    } catch (error) {
        showToast(`Falha ao criar regra: ${error.message}`, 'danger');
    }
});

async function loadConfig() {
    try {
        const cfg = await apiFetch('/api/config');
        configView.textContent = JSON.stringify(cfg, null, 2);
    } catch (error) {
        showToast(`Erro ao carregar configuração: ${error.message}`, 'danger');
    }
}

document.getElementById('reload-config').addEventListener('click', loadConfig);

document.getElementById('save-config').addEventListener('click', async () => {
    if (!configEditor.value.trim()) {
        configFeedback.textContent = 'Informe um JSON para atualizar.';
        configFeedback.classList.add('text-danger');
        return;
    }
    try {
        const payload = JSON.parse(configEditor.value);
        const response = await apiFetch('/api/config', { method: 'PUT', json: payload });
        configView.textContent = JSON.stringify(response, null, 2);
        configFeedback.textContent = 'Configuração aplicada com sucesso.';
        configFeedback.classList.remove('text-danger');
        showToast('Configuração atualizada.', 'success');
    } catch (error) {
        configFeedback.textContent = error.message;
        configFeedback.classList.add('text-danger');
    }
});

async function loadWhitelist() {
    try {
        const data = await apiFetch('/api/whitelist');
        whitelistView.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        showToast(`Erro ao carregar whitelist: ${error.message}`, 'danger');
    }
}

document.getElementById('save-whitelist').addEventListener('click', async () => {
    try {
        const payload = whitelistEditor.value.trim() ? JSON.parse(whitelistEditor.value) : { ips: [], cidrs: [] };
        await apiFetch('/api/whitelist', { method: 'PUT', json: payload });
        whitelistFeedback.textContent = 'Whitelist salva com sucesso.';
        whitelistFeedback.classList.remove('text-danger');
        showToast('Whitelist atualizada.', 'success');
        await loadWhitelist();
    } catch (error) {
        whitelistFeedback.textContent = error.message;
        whitelistFeedback.classList.add('text-danger');
    }
});

async function loadFirewallStatus() {
    try {
        const data = await apiFetch('/api/firewall/status');
        const entries = {
            Backend: data.backend,
            'Backends disponíveis': (data.available_backends || []).join(', ') || 'Nenhum',
            Detalhes: data.detail || '-'
        };
        firewallStatus.innerHTML = Object.entries(entries)
            .map(
                ([label, value]) => `
                <dt class="col-4">${label}</dt>
                <dd class="col-8">${value}</dd>`
            )
            .join('');
    } catch (error) {
        showToast(`Erro ao buscar status do firewall: ${error.message}`, 'danger');
    }
}

async function loadGrafana() {
    try {
        const dashboards = await apiFetch('/api/grafana/dashboards');
        grafanaList.innerHTML = dashboards.length
            ? dashboards
                  .map(
                      (item) => `
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <span>${item.name}</span>
                        <span class="badge bg-secondary">${formatBytes(item.size || 0)}</span>
                    </li>`
                  )
                  .join('')
            : '<li class="list-group-item">Nenhum dashboard cadastrado.</li>';
    } catch (error) {
        showToast(`Erro ao carregar dashboards: ${error.message}`, 'danger');
    }
}

Array.from(document.querySelectorAll('#tab-management [data-action]')).forEach((button) => {
    button.addEventListener('click', async () => {
        const action = button.dataset.action;
        try {
            const response = await apiFetch(action, { method: 'POST' });
            showToast(response.message || 'Ação executada.', 'success');
        } catch (error) {
            showToast(`Falha ao executar ação: ${error.message}`, 'danger');
        }
    });
});

async function loadBGPPeers() {
    try {
        const peers = await apiFetch('/api/bgp/peers');
        bgpTable.innerHTML = peers.length
            ? peers
                  .map(
                      (peer) => `
                    <tr>
                        <td>${peer.source_name}</td>
                        <td>${peer.peer_ip}</td>
                        <td>${peer.remote_as || '-'}</td>
                        <td>${peer.state || peer.admin_status || '-'}</td>
                    </tr>`
                  )
                  .join('')
            : '<tr><td colspan="4" class="text-center text-secondary">Nenhum peer disponível.</td></tr>';
    } catch (error) {
        showToast(`Erro ao carregar peers BGP: ${error.message}`, 'danger');
    }
}

async function loadInterfaces() {
    try {
        const data = await apiFetch('/api/interfaces');
        const rows = [];
        Object.entries(data || {}).forEach(([device, info]) => {
            const vendor = info.vendor || '-';
            const ifaceMap = info.interfaces || {};
            Object.values(ifaceMap).forEach((iface) => {
                rows.push(`
                    <tr>
                        <td>${device} <small class="text-secondary">(${vendor})</small></td>
                        <td>${iface.snmp_name || iface.name || '-'}</td>
                        <td>${iface.snmp_desc || iface.desc || '-'}</td>
                    </tr>`);
            });
        });
        interfacesTable.innerHTML = rows.length
            ? rows.join('')
            : '<tr><td colspan="3" class="text-center text-secondary">Nenhuma interface conhecida.</td></tr>';
    } catch (error) {
        showToast(`Erro ao carregar interfaces: ${error.message}`, 'danger');
    }
}

async function loadFlows() {
    try {
        const limit = Number(flowLimitInput.value) || 20;
        const flows = await apiFetch(`/flows?limit=${limit}`);
        flowsTable.innerHTML = flows.length
            ? flows
                  .map(
                      (flow) => `
                    <tr>
                        <td>${flow.SourceName || '-'}</td>
                        <td>${flow.SrcAddr} → ${flow.DstAddr}</td>
                        <td>${flow.Proto}/${flow.DstPort}</td>
                        <td>${formatBytes(flow.Bytes)}</td>
                        <td>${formatDate(flow.TimeReceived)}</td>
                    </tr>`
                  )
                  .join('')
            : '<tr><td colspan="5" class="text-center text-secondary">Nenhum flow encontrado.</td></tr>';
    } catch (error) {
        showToast(`Erro ao carregar flows: ${error.message}`, 'danger');
    }
}

flowLimitInput.addEventListener('change', () => {
    loadFlows();
});

const tabLoaders = new Map([
    ['#tab-dashboard', loadDashboard],
    ['#tab-config', loadConfig],
    ['#tab-whitelist', async () => { await loadWhitelist(); await loadFirewallStatus(); }],
    ['#tab-management', async () => { await loadGrafana(); await loadBGPPeers(); }],
    ['#tab-data', async () => { await loadInterfaces(); await loadFlows(); }],
]);

document.getElementById('app-tabs').addEventListener('shown.bs.tab', async (event) => {
    const target = event.target.getAttribute('data-target');
    const loader = tabLoaders.get(target);
});

checkSession();
