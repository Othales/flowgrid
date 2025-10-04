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
const routerModalEl = document.getElementById('router-modal');
const routerModal = routerModalEl ? new bootstrap.Modal(routerModalEl) : null;
const routerModalTitle = document.getElementById('router-modal-title');
const routerFormSubmit = document.getElementById('router-form-submit');
const routerFormFeedback = document.getElementById('router-form-feedback');
const routerVersionSelect = document.getElementById('router-version');
const routerCommunityGroup = document.getElementById('router-community-group');
const routerV3Fields = document.getElementById('router-v3-fields');
const openRouterModalBtn = document.getElementById('open-router-modal');
const routersTable = document.querySelector('#routers-table tbody');
const alertsTable = document.querySelector('#alerts-table tbody');
const alertForm = document.getElementById('alert-form');
const alertModalEl = document.getElementById('alert-modal');
const alertModal = alertModalEl ? new bootstrap.Modal(alertModalEl) : null;
const alertModalTitle = document.getElementById('alert-modal-title');
const alertSubmitLabel = document.getElementById('alert-submit-label');
const alertFormFeedback = document.getElementById('alert-form-feedback');
const alertActionOptions = Array.from(document.querySelectorAll('.alert-action-toggle'));
const alertActionsPreview = document.getElementById('alert-actions-preview');
const alertActionsCustomInput = document.getElementById('alert-actions-custom');
const alertFilterSuggestions = document.getElementById('alert-filter-suggestions');
const openAlertModalBtn = document.getElementById('open-alert-modal');
const openAlertModalSecondary = document.getElementById('open-alert-modal-secondary');
const openAlertDocsBtn = document.getElementById('open-alert-docs');
const alertFilterJoinRadios = Array.from(document.querySelectorAll('input[name="alert-filter-join"]'));
const jsonModalEl = document.getElementById('json-editor-modal');
const jsonModal = jsonModalEl ? new bootstrap.Modal(jsonModalEl) : null;
const jsonModalTitle = document.getElementById('json-modal-title');
const jsonModalTextarea = document.getElementById('json-modal-textarea');
const jsonModalFeedback = document.getElementById('json-modal-feedback');
const jsonModalSave = document.getElementById('json-modal-save');
const jsonModalRefresh = document.getElementById('json-modal-refresh');
const configSummary = document.getElementById('config-summary');
const configForm = document.getElementById('config-form');
const configFormFeedback = document.getElementById('config-form-feedback');
const firewallStatus = document.getElementById('firewall-status');
const whitelistCurrent = document.getElementById('whitelist-current');
const whitelistForm = document.getElementById('whitelist-form');
const whitelistIPsInput = document.getElementById('whitelist-ips');
const whitelistCIDRsInput = document.getElementById('whitelist-cidrs');
const whitelistFeedback = document.getElementById('whitelist-feedback');
const reloadWhitelistBtn = document.getElementById('reload-whitelist');
const configControls = {
    netflow: document.getElementById('config-netflow'),
    sflow: document.getElementById('config-sflow'),
    http: document.getElementById('config-http'),
    updateInterval: document.getElementById('config-update-interval'),
    cleanTime: document.getElementById('config-clean-time'),
    dataPath: document.getElementById('config-data-path'),
    maxDisk: document.getElementById('config-max-disk'),
    password: document.getElementById('config-password'),
    apiNetwork: document.getElementById('config-api-network'),
    internalBlocks: document.getElementById('config-internal-blocks'),
    internalASNs: document.getElementById('config-internal-asns'),
    favoriteASNs: document.getElementById('config-favorite-asns'),
    favoriteIPs: document.getElementById('config-favorite-ips'),
    ignoredIPs: document.getElementById('config-ignored-ips'),
    favoriteServices: document.getElementById('config-favorite-services'),
    ignoredASNs: document.getElementById('config-ignored-asns'),
    notificationApply: document.getElementById('config-notification-apply'),
    telegramEnabled: document.getElementById('config-telegram-enabled'),
    telegramBot: document.getElementById('config-telegram-bot'),
    telegramProxy: document.getElementById('config-telegram-proxy'),
    telegramChatIDs: document.getElementById('config-telegram-chatids'),
    telegramReplyIDs: document.getElementById('config-telegram-replyids'),
    telegramAlerts: document.getElementById('config-telegram-alerts'),
    telegramSystem: document.getElementById('config-telegram-system'),
    emailEnabled: document.getElementById('config-email-enabled'),
    emailHost: document.getElementById('config-email-host'),
    emailPort: document.getElementById('config-email-port'),
    emailFrom: document.getElementById('config-email-from'),
    emailUsername: document.getElementById('config-email-username'),
    emailPassword: document.getElementById('config-email-password'),
    emailTo: document.getElementById('config-email-to'),
    emailReplyTo: document.getElementById('config-email-replyto'),
    emailTLS: document.getElementById('config-email-tls'),
    emailStartTLS: document.getElementById('config-email-starttls'),
    firewallNetflow: document.getElementById('config-firewall-netflow'),
    firewallSflow: document.getElementById('config-firewall-sflow'),
    firewallAPI: document.getElementById('config-firewall-api'),
    firewallExport: document.getElementById('config-firewall-export'),
};
const routerControls = {
    name: document.getElementById('router-name'),
    ip: document.getElementById('router-ip'),
    port: document.getElementById('router-port'),
    community: document.getElementById('router-community'),
    user: document.getElementById('router-user'),
    auth: document.getElementById('router-auth'),
    authPass: document.getElementById('router-authpass'),
    priv: document.getElementById('router-priv'),
    privPass: document.getElementById('router-privpass'),
};
const grafanaList = document.getElementById('grafana-list');
const bgpTable = document.querySelector('#bgp-table tbody');
const interfacesTable = document.querySelector('#interfaces-table tbody');
const flowsTable = document.querySelector('#flows-table tbody');
const flowLimitInput = document.getElementById('flow-limit');
const systemCards = document.getElementById('system-cards');
const statsOverview = document.getElementById('stats-overview');
const topSourcesTable = document.querySelector('#top-sources-table tbody');
const topAppsTable = document.querySelector('#top-apps-table tbody');
const routerSummary = document.getElementById('router-summary');
const alertsFlowchart = document.getElementById('alerts-flowchart');

let sessionCache = null;
let vendorsCache = [];
let routersCache = [];
let alertsCache = [];
let editingRouterName = null;
let editingAlertName = null;
let jsonModalContext = null;

if (routerVersionSelect) {
    routerVersionSelect.addEventListener('change', updateRouterVersionFields);
    updateRouterVersionFields();
}

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

function splitList(value = '', asNumber = false) {
    return value
        .split(/[,\n]+/)
        .map((item) => item.trim())
        .filter(Boolean)
        .map((item) => (asNumber ? Number(item) : item))
        .filter((item) => (asNumber ? Number.isFinite(item) : true));
}

function joinMultiline(values = []) {
    if (!Array.isArray(values) || values.length === 0) return '';
    return values.join('\n');
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
    let hadError = false;
    try {
        await Promise.all([
            loadDashboard(),
            loadConfig(),
            loadWhitelist(),
            loadFirewallStatus(),
            loadGrafana(),
            loadBGPPeers(),
            loadInterfaces(),
            loadFlows(),
        ]);

        const routersOk = await loadRouters();
        if (routersOk === false) hadError = true;

        const summaryOk = await loadRouterSummary();
        if (summaryOk === false) hadError = true;

        const alertsOk = await loadAlerts();
        if (alertsOk === false) hadError = true;

        const insightsOk = await loadAlertInsights();
        if (insightsOk === false) hadError = true;

        if (hadError) {
            showToast('Nem todos os dados foram atualizados, verifique os avisos exibidos.', 'warning');
        } else {
            showToast('Dados atualizados.', 'success');
        }
    } catch (error) {
        showToast(`Erro ao atualizar: ${error.message}`, 'danger');
    }
});

async function loadVendors() {
    try {
        vendorsCache = await apiFetch('/api/vendors');
        routerVendorSelect.innerHTML = vendorsCache.map((vendor) => `<option value="${vendor}">${vendor}</option>`).join('');
        if (!routerVendorSelect.value && vendorsCache.length > 0) {
            routerVendorSelect.value = vendorsCache[0];
        }
    } catch (error) {
        showToast(`Falha ao carregar vendors: ${error.message}`, 'danger');
    }
}

function updateRouterVersionFields() {
    if (!routerVersionSelect) return;
    const version = routerVersionSelect.value;
    if (version === '3') {
        routerCommunityGroup?.classList.add('d-none');
        routerV3Fields?.classList.remove('d-none');
    } else {
        routerCommunityGroup?.classList.remove('d-none');
        routerV3Fields?.classList.add('d-none');
    }
}

function ensureVendorOption(vendor) {
    if (!vendor || !routerVendorSelect) return;
    if (![...routerVendorSelect.options].some((opt) => opt.value === vendor)) {
        const option = document.createElement('option');
        option.value = vendor;
        option.textContent = vendor;
        routerVendorSelect.appendChild(option);
    }
}

function openRouterModal(router = null) {
    if (!routerModal || !routerForm) return;
    if (routerVendorSelect && routerVendorSelect.options.length === 0 && vendorsCache.length === 0) {
        loadVendors();
    }
    routerForm.reset();
    routerFormFeedback.textContent = '';
    editingRouterName = router ? router.name : null;
    const submitLabel = routerFormSubmit?.querySelector('span');
    if (router) {
        routerModalTitle.textContent = `Editar roteador`;
        if (submitLabel) submitLabel.textContent = 'Salvar alterações';
    } else {
        routerModalTitle.textContent = 'Novo roteador';
        if (submitLabel) submitLabel.textContent = 'Adicionar roteador';
    }

    const snmp = router?.snmp || {};
    routerControls.name.value = router?.name || '';
    if (router?.vendor) {
        ensureVendorOption(router.vendor);
        routerVendorSelect.value = router.vendor;
    } else if (!routerVendorSelect.value && vendorsCache.length > 0) {
        routerVendorSelect.value = vendorsCache[0];
    }
    routerControls.ip.value = snmp.ip || '';
    routerControls.port.value = snmp.port || 161;
    routerVersionSelect.value = snmp.version || '2c';
    routerControls.community.value = snmp.community || 'public';
    routerControls.user.value = snmp.user || '';
    routerControls.auth.value = snmp.auth || '';
    routerControls.authPass.value = snmp.authpass || '';
    routerControls.priv.value = snmp.priv || '';
    routerControls.privPass.value = snmp.privpass || '';
    updateRouterVersionFields();
    routerModal.show();
}

openRouterModalBtn?.addEventListener('click', () => openRouterModal());
routerModalEl?.addEventListener('hidden.bs.modal', () => {
    editingRouterName = null;
    routerForm.reset();
    routerControls.community.value = 'public';
    routerControls.port.value = 161;
    if (routerFormSubmit) {
        const submitLabel = routerFormSubmit.querySelector('span');
        if (submitLabel) submitLabel.textContent = 'Salvar roteador';
        routerFormSubmit.disabled = false;
    }
    routerFormFeedback.textContent = '';
    updateRouterVersionFields();
});

function setAlertActionButtonState(button, active) {
    if (!button) return;
    button.classList.toggle('btn-primary', active);
    button.classList.toggle('btn-outline-light', !active);
}

function setAlertActionSelections(values = []) {
    const normalized = new Set(values.map((value) => value.toLowerCase()));
    alertActionOptions.forEach((button) => {
        const active = normalized.has(button.dataset.value?.toLowerCase());
        button.dataset.active = active ? 'true' : 'false';
        setAlertActionButtonState(button, active);
    });
    renderAlertActionsPreview();
}

function getSelectedAlertActions() {
    const selected = new Set();
    alertActionOptions.forEach((button) => {
        if (button.dataset.active === 'true') {
            selected.add(button.dataset.value);
        }
    });
    splitList(alertActionsCustomInput?.value || '').forEach((item) => selected.add(item));
    return Array.from(selected);
}

function renderAlertActionsPreview() {
    if (!alertActionsPreview) return;
    const actions = getSelectedAlertActions();
    if (actions.length === 0) {
        alertActionsPreview.textContent = 'Nenhuma ação selecionada.';
        return;
    }
    alertActionsPreview.innerHTML = actions
        .map((action) => `<span class="badge bg-primary me-1 mb-1">${action}</span>`)
        .join('');
}

function getSelectedFilterJoin() {
    const checked = document.querySelector('input[name="alert-filter-join"]:checked');
    return checked ? checked.value : 'AND';
}

function setSelectedFilterJoin(value) {
    alertFilterJoinRadios.forEach((radio) => {
        radio.checked = radio.value === value;
    });
}

function setJsonModalFeedback(message = '', variant = '') {
    if (!jsonModalFeedback) return;
    jsonModalFeedback.textContent = message;
    jsonModalFeedback.classList.remove('text-danger', 'text-success', 'text-info');
    if (variant) {
        jsonModalFeedback.classList.add(`text-${variant}`);
    }
}

function openAlertModal(rule = null) {
    if (!alertModal || !alertForm) return;
    alertForm.reset();
    alertFormFeedback.textContent = '';
    editingAlertName = rule ? rule.name : null;
    if (rule) {
        alertModalTitle.textContent = `Editar fluxo`;
        if (alertSubmitLabel) alertSubmitLabel.textContent = 'Salvar alterações';
    } else {
        alertModalTitle.textContent = 'Novo fluxo de alerta';
        if (alertSubmitLabel) alertSubmitLabel.textContent = 'Criar fluxo';
    }
    document.getElementById('alert-name').value = rule?.name || '';
    const filterValue = rule?.filter || '';
    document.getElementById('alert-filter').value = filterValue;
    setSelectedFilterJoin(filterValue.includes(' OR ') ? 'OR' : 'AND');
    document.getElementById('alert-condition').value = rule?.condition || '';
    document.getElementById('alert-window').value = rule?.time_window_seconds || 60;
    document.getElementById('alert-comment').value = rule?.comment || '';
    document.getElementById('alert-enabled').checked = rule ? Boolean(rule.enabled) : true;
    const actions = Array.isArray(rule?.actions) ? rule.actions : [];
    const knownActions = new Set(alertActionOptions.map((button) => button.dataset.value?.toLowerCase()));
    const toggleActions = actions.filter((action) => knownActions.has(action.toLowerCase()));
    const customActions = actions.filter((action) => !knownActions.has(action.toLowerCase()));
    alertActionsCustomInput.value = customActions.join(',');
    setAlertActionSelections(toggleActions);
    renderAlertActionsPreview();
    alertModal.show();
}

alertActionOptions.forEach((button) => {
    button.addEventListener('click', () => {
        const isActive = button.dataset.active === 'true';
        button.dataset.active = isActive ? 'false' : 'true';
        setAlertActionButtonState(button, !isActive);
        renderAlertActionsPreview();
    });
});

alertActionsCustomInput?.addEventListener('input', renderAlertActionsPreview);

alertFilterSuggestions?.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-filter]');
    if (!button) return;
    const field = button.dataset.filter;
    const filterInput = document.getElementById('alert-filter');
    if (!filterInput) return;
    const current = filterInput.value.trim();
    const joiner = getSelectedFilterJoin();
    filterInput.value = current ? `${current} ${joiner} ${field}=` : `${field}=`;
    filterInput.focus();
});

openAlertModalBtn?.addEventListener('click', () => openAlertModal());
openAlertModalSecondary?.addEventListener('click', () => openAlertModal());
openAlertDocsBtn?.addEventListener('click', () => {
    showToast('Exemplos: SrcASN=15169 OR Country=BR • Bps > 1000000 AND Packets > 1000 • ThreatCategory=botnet AND Action=block', 'info');
});

alertModalEl?.addEventListener('hidden.bs.modal', () => {
    editingAlertName = null;
    alertFormFeedback.textContent = '';
    if (alertSubmitLabel) alertSubmitLabel.textContent = 'Criar fluxo';
    alertForm.reset();
    setSelectedFilterJoin('AND');
    setAlertActionSelections([]);
});

setAlertActionSelections([]);

jsonModalSave?.addEventListener('click', saveJsonModal);
jsonModalRefresh?.addEventListener('click', refreshPeersFromModal);
jsonModalEl?.addEventListener('hidden.bs.modal', () => {
    jsonModalContext = null;
    if (jsonModalTextarea) {
        jsonModalTextarea.value = '';
        jsonModalTextarea.readOnly = false;
    }
    if (jsonModalSave) {
        jsonModalSave.disabled = false;
    }
    configureJsonModal('');
    setJsonModalFeedback('');
});

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

function buildSnmpPayloadFromRouter(router) {
    const snmp = router?.snmp || {};
    const payload = {
        ip: snmp.ip || '',
        port: snmp.port || 161,
        version: snmp.version || '2c',
        community: snmp.community || 'public',
        user: snmp.user || '',
        auth: snmp.auth || '',
        authpass: snmp.authpass || '',
        priv: snmp.priv || '',
        privpass: snmp.privpass || '',
    };
    if (payload.version !== '3') {
        delete payload.user;
        delete payload.auth;
        delete payload.authpass;
        delete payload.priv;
        delete payload.privpass;
    }
    return payload;
}

async function runSnmpTestForRouter(router) {
    if (!router) {
        showToast('Não foi possível carregar os dados do roteador para o teste SNMP.', 'danger');
        return;
    }
    const payload = buildSnmpPayloadFromRouter(router);
    if (!payload.ip) {
        showToast(`Roteador ${router.name} não possui IP SNMP configurado.`, 'warning');
        return;
    }
    showToast(`Testando SNMP em ${router.name}...`, 'info');
    try {
        const response = await apiFetch('/api/snmp/test', { method: 'POST', json: payload });
        const detail = response.description ? ` (${response.description})` : '';
        showToast(`SNMP ok em ${router.name}${detail}`, 'success');
    } catch (error) {
        showToast(`Falha no SNMP de ${router.name}: ${error.message}`, 'danger');
    }
}

function configureJsonModal(mode) {
    if (!jsonModalRefresh) return;
    if (mode === 'peers') {
        jsonModalRefresh.classList.remove('d-none');
        jsonModalRefresh.disabled = false;
    } else {
        jsonModalRefresh.classList.add('d-none');
        jsonModalRefresh.disabled = true;
    }
}

async function openJsonModalForRouter(mode, routerName) {
    if (!jsonModal || !jsonModalTextarea || !jsonModalSave || !routerName) return;
    jsonModalContext = { mode, routerName };
    setJsonModalFeedback('Carregando...', 'info');
    jsonModalTitle.textContent = mode === 'peers' ? `Peers de ${routerName}` : `Interfaces de ${routerName}`;
    jsonModalTextarea.value = '';
    jsonModalTextarea.readOnly = true;
    jsonModalSave.disabled = true;
    configureJsonModal(mode);
    jsonModal.show();
    try {
        const endpoint = mode === 'peers'
            ? `/api/routers/${encodeURIComponent(routerName)}/peers`
            : `/api/routers/${encodeURIComponent(routerName)}/interfaces`;
        const data = await apiFetch(endpoint);
        jsonModalTextarea.value = JSON.stringify(data, null, 2);
        jsonModalTextarea.readOnly = false;
        jsonModalSave.disabled = false;
        const hint = mode === 'peers'
            ? 'Use "Atualizar via SNMP" para sincronizar com o roteador.'
            : 'Edite os campos conforme necessário e salve para atualizar o cache local.';
        setJsonModalFeedback(hint, 'info');
    } catch (error) {
        const message = error.message || 'Não foi possível carregar os dados.';
        jsonModalTextarea.value = mode === 'peers' ? '[]' : JSON.stringify({ vendor: '', source_ip: '', interfaces: {} }, null, 2);
        jsonModalTextarea.readOnly = false;
        jsonModalSave.disabled = false;
        if (mode === 'peers' && jsonModalRefresh) {
            jsonModalRefresh.disabled = false;
        }
        const variant = /sem|nenhum/i.test(message) ? 'info' : 'danger';
        setJsonModalFeedback(message, variant);
    }
}

async function saveJsonModal() {
    if (!jsonModalContext || !jsonModalTextarea || !jsonModalSave) return;
    const { mode, routerName } = jsonModalContext;
    const endpoint = mode === 'peers'
        ? `/api/routers/${encodeURIComponent(routerName)}/peers`
        : `/api/routers/${encodeURIComponent(routerName)}/interfaces`;
    let payload;
    try {
        payload = JSON.parse(jsonModalTextarea.value || (mode === 'peers' ? '[]' : '{}'));
    } catch (error) {
        setJsonModalFeedback(`JSON inválido: ${error.message}`, 'danger');
        return;
    }
    setJsonModalFeedback('Salvando alterações...', 'info');
    jsonModalTextarea.readOnly = true;
    jsonModalSave.disabled = true;
    if (jsonModalRefresh && mode === 'peers') {
        jsonModalRefresh.disabled = true;
    }
    try {
        await apiFetch(endpoint, { method: 'PUT', json: payload });
        const successMessage = mode === 'peers'
            ? `Peers de ${routerName} atualizados.`
            : `Interfaces de ${routerName} atualizadas.`;
        showToast(successMessage, 'success');
        if (mode === 'peers') {
            await loadBGPPeers();
            if (jsonModalRefresh) jsonModalRefresh.disabled = false;
        } else {
            await loadInterfaces();
        }
        jsonModalTextarea.readOnly = false;
        jsonModalSave.disabled = false;
        setJsonModalFeedback('Alterações salvas.', 'success');
    } catch (error) {
        jsonModalTextarea.readOnly = false;
        jsonModalSave.disabled = false;
        if (jsonModalRefresh && mode === 'peers') {
            jsonModalRefresh.disabled = false;
        }
        setJsonModalFeedback(error.message, 'danger');
    }
}

async function refreshPeersFromModal() {
    if (!jsonModalContext || jsonModalContext.mode !== 'peers' || !jsonModalTextarea || !jsonModalRefresh) {
        return;
    }
    const { routerName } = jsonModalContext;
    setJsonModalFeedback('Consultando SNMP...', 'info');
    jsonModalTextarea.readOnly = true;
    jsonModalSave.disabled = true;
    jsonModalRefresh.disabled = true;
    try {
        const data = await apiFetch(`/api/routers/${encodeURIComponent(routerName)}/peers/refresh`, {
            method: 'POST',
        });
        jsonModalTextarea.value = JSON.stringify(data, null, 2);
        setJsonModalFeedback('Peers sincronizados com o roteador.', 'success');
        await loadBGPPeers();
    } catch (error) {
        setJsonModalFeedback(error.message, 'danger');
    } finally {
        jsonModalTextarea.readOnly = false;
        jsonModalSave.disabled = false;
        jsonModalRefresh.disabled = false;
    }
}

async function loadRouters() {
    try {
        const routers = await apiFetch('/api/routers');
        routersCache = Array.isArray(routers) ? routers : [];
        if (routersCache.length === 0) {
            routersTable.innerHTML = '<tr><td colspan="5" class="text-center text-secondary">Nenhum roteador cadastrado.</td></tr>';
            return true;
        }
        routersTable.innerHTML = routersCache
            .map((router) => {
                const snmp = router.snmp || {};
                return `
                <tr>
                    <td>${router.name}</td>
                    <td>${router.vendor}</td>
                    <td>${snmp.ip || '-'}</td>
                    <td>v${snmp.version || '-'} @ ${snmp.port || 161}</td>
                    <td class="text-nowrap">
                        <div class="btn-group btn-group-sm" role="group">
                            <button class="btn btn-outline-light" data-action="edit-router" data-name="${encodeURIComponent(router.name)}">
                                <i class="fa-solid fa-pen"></i>
                            </button>
                            <button class="btn btn-outline-light dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-expanded="false">
                                <span class="visually-hidden">Ações</span>
                            </button>
                            <ul class="dropdown-menu dropdown-menu-dark dropdown-menu-end">
                                <li><button class="dropdown-item" type="button" data-action="snmp-test" data-name="${encodeURIComponent(router.name)}"><i class="fa-solid fa-stethoscope me-2"></i>Testar SNMP</button></li>
                                <li><button class="dropdown-item" type="button" data-action="interfaces-json" data-name="${encodeURIComponent(router.name)}"><i class="fa-solid fa-code me-2"></i>Interfaces (JSON)</button></li>
                                <li><button class="dropdown-item" type="button" data-action="peers-json" data-name="${encodeURIComponent(router.name)}"><i class="fa-solid fa-cloud me-2"></i>Peers (JSON)</button></li>
                                <li><button class="dropdown-item" type="button" data-action="peers-refresh" data-name="${encodeURIComponent(router.name)}"><i class="fa-solid fa-rotate me-2"></i>Atualizar peers SNMP</button></li>
                                <li><hr class="dropdown-divider" /></li>
                                <li><button class="dropdown-item text-danger" type="button" data-action="delete-router" data-name="${encodeURIComponent(router.name)}"><i class="fa-solid fa-trash me-2"></i>Remover</button></li>
                            </ul>
                        </div>
                    </td>
                </tr>`;
            })
            .join('');
        return true;
    } catch (error) {
        routersCache = [];
        showToast(`Erro ao carregar roteadores: ${error.message}`, 'danger');
        return false;
    }
}

document.getElementById('reload-routers').addEventListener('click', async () => {
    await loadRouters();
    await loadRouterSummary();
});

async function loadRouterSummary() {
    if (!routerSummary) return true;
    try {
        const [stats, dashboard] = await Promise.all([
            apiFetch('/stats'),
            apiFetch('/api/dashboard/stats?hours=24'),
        ]);
        renderRouterSummary(stats, dashboard);
        return true;
    } catch (error) {
        routerSummary.innerHTML = '<div class="col-12 text-danger">Não foi possível atualizar a visão geral SNMP.</div>';
        showToast(`Erro ao atualizar visão geral: ${error.message}`, 'danger');
        return false;
    }
}

function renderRouterSummary(stats = {}, dashboard = {}) {
    if (!routerSummary) return;
    const totalRouters = routersCache.length;
    const topSources = Array.isArray(dashboard.top_sources) ? dashboard.top_sources : [];
    const activeSet = new Set(topSources.map((item) => item.source_name));
    const activeCount = routersCache.filter((router) => activeSet.has(router.name)).length;
    const inactiveCount = Math.max(totalRouters - activeCount, 0);
    const lastActiveISO = topSources.reduce((latest, item) => {
        if (!item.last_active) return latest;
        if (!latest) return item.last_active;
        return new Date(item.last_active) > new Date(latest) ? item.last_active : latest;
    }, null);
    const vendorCounts = routersCache.reduce((acc, router) => {
        const key = router.vendor || 'Desconhecido';
        acc[key] = (acc[key] || 0) + 1;
        return acc;
    }, {});
    const vendorEntries = Object.entries(vendorCounts);
    const topVendor = vendorEntries.sort((a, b) => b[1] - a[1])[0];

    const cards = [
        {
            icon: 'server',
            label: 'Fontes cadastradas',
            value: formatNumber(totalRouters),
            detail: totalRouters
                ? `${formatNumber(activeCount)} ativos • ${formatNumber(inactiveCount)} sem tráfego recente`
                : 'Cadastre um roteador para iniciar o monitoramento',
        },
        {
            icon: 'clock-rotate-left',
            label: 'Última atividade',
            value: lastActiveISO ? formatDate(lastActiveISO) : '-',
            detail: activeCount
                ? `Referência: ${topSources[0]?.source_name || 'fonte desconhecida'}`
                : 'Sem dados de fluxo nas últimas 24h',
        },
        {
            icon: 'network-wired',
            label: 'Interfaces SNMP',
            value: formatNumber(stats.interface_count || 0),
            detail: (stats.snmp_errors || 0)
                ? `${formatNumber(stats.snmp_errors)} erros SNMP reportados`
                : 'Nenhum erro SNMP registrado',
        },
        {
            icon: 'chart-pie',
            label: 'Diversidade de vendors',
            value: vendorEntries.length ? `${formatNumber(vendorEntries.length)} vendors` : 'Nenhum vendor',
            detail: topVendor && totalRouters
                ? `Topo: ${topVendor[0]} (${formatPercent((topVendor[1] / totalRouters) * 100)})`
                : 'Aguardando cadastro de fontes',
        },
    ];

    routerSummary.innerHTML = cards
        .map(
            (card) => `
            <div class="col-md-6 col-xl-3">
                <div class="card h-100 bg-body-tertiary">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <span class="text-secondary">${card.label}</span>
                            <i class="fa-solid fa-${card.icon} text-primary"></i>
                        </div>
                        <p class="fs-4 fw-semibold mt-2 mb-1">${card.value}</p>
                        <p class="text-secondary mb-0">${card.detail}</p>
                    </div>
                </div>
            </div>`
        )
        .join('');
}

routersTable.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-action]');
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
            await loadRouterSummary();
        } catch (error) {
            showToast(`Falha ao remover: ${error.message}`, 'danger');
        }
    }

    if (action === 'edit-router') {
        const current = routersCache.find((item) => item.name === name);
        if (current) {
            openRouterModal(current);
            return;
        }
        try {
            const fetched = await apiFetch(`/api/routers/${encodeURIComponent(name)}`);
            openRouterModal(fetched);
        } catch (error) {
            showToast(`Falha ao carregar roteador: ${error.message}`, 'danger');
        }
    }

    if (action === 'snmp-test') {
        const current = routersCache.find((item) => item.name === name);
        await runSnmpTestForRouter(current || null);
        return;
    }

    if (action === 'interfaces-json') {
        await openJsonModalForRouter('interfaces', name);
        return;
    }

    if (action === 'peers-json') {
        await openJsonModalForRouter('peers', name);
        return;
    }

    if (action === 'peers-refresh') {
        try {
            const data = await apiFetch(`/api/routers/${encodeURIComponent(name)}/peers/refresh`, { method: 'POST' });
            showToast(`Peers atualizados via SNMP para ${name}.`, 'success');
            await loadBGPPeers();
            if (jsonModalContext && jsonModalContext.mode === 'peers' && jsonModalContext.routerName === name && jsonModalTextarea) {
                jsonModalTextarea.value = JSON.stringify(data, null, 2);
                setJsonModalFeedback('Peers sincronizados com o roteador.', 'success');
            }
        } catch (error) {
            showToast(`Falha ao atualizar peers de ${name}: ${error.message}`, 'danger');
        }
    }
});

routerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!routerForm) return;
    const payload = {
        name: routerControls.name.value.trim(),
        vendor: routerVendorSelect.value,
        snmp: {
            ip: routerControls.ip.value.trim(),
            community: routerControls.community.value.trim() || 'public',
            port: Number(routerControls.port.value) || 161,
            version: routerVersionSelect.value,
            user: routerControls.user.value.trim(),
            auth: routerControls.auth.value,
            authpass: routerControls.authPass.value,
            priv: routerControls.priv.value,
            privpass: routerControls.privPass.value,
        },
    };
    if (!payload.name || !payload.snmp.ip) {
        routerFormFeedback.textContent = 'Informe nome e IP do roteador.';
        return;
    }
    if (!payload.vendor) {
        routerFormFeedback.textContent = 'Selecione um vendor suportado.';
        return;
    }
    if (payload.snmp.version !== '3') {
        delete payload.snmp.user;
        delete payload.snmp.auth;
        delete payload.snmp.authpass;
        delete payload.snmp.priv;
        delete payload.snmp.privpass;
    }
    const submitLabel = routerFormSubmit?.querySelector('span');
    if (routerFormSubmit) {
        routerFormSubmit.disabled = true;
        if (submitLabel) submitLabel.textContent = editingRouterName ? 'Salvando...' : 'Adicionando...';
    }
    routerFormFeedback.textContent = '';
    try {
        if (editingRouterName) {
            await apiFetch(`/api/routers/${encodeURIComponent(editingRouterName)}`, { method: 'PUT', json: payload });
            showToast('Roteador atualizado.', 'success');
        } else {
            await apiFetch('/api/routers', { method: 'POST', json: payload });
            showToast('Roteador cadastrado.', 'success');
        }
        routerModal?.hide();
        await loadRouters();
        await loadRouterSummary();
    } catch (error) {
        routerFormFeedback.textContent = error.message;
    } finally {
        if (routerFormSubmit) {
            routerFormSubmit.disabled = false;
            if (submitLabel) submitLabel.textContent = editingRouterName ? 'Salvar alterações' : 'Adicionar roteador';
        }
    }
});

async function loadAlerts() {
    try {
        const alerts = await apiFetch('/api/alerts');
        alertsCache = Array.isArray(alerts) ? alerts : [];
        if (alertsCache.length === 0) {
            alertsTable.innerHTML = '<tr><td colspan="4" class="text-center text-secondary">Nenhuma regra configurada.</td></tr>';
            return true;
        }
        alertsTable.innerHTML = alertsCache
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
        return true;
    } catch (error) {
        alertsCache = [];
        showToast(`Falha ao carregar alertas: ${error.message}`, 'danger');
        return false;
    }
}

document.getElementById('reload-alerts').addEventListener('click', async () => {
    await loadAlerts();
    await loadAlertInsights();
});

async function loadAlertInsights() {
    if (!alertsFlowchart) return true;
    try {
        const [stats, dashboard] = await Promise.all([
            apiFetch('/stats'),
            apiFetch('/api/dashboard/stats?hours=24'),
        ]);
        renderAlertFlowchart(stats, dashboard);
        return true;
    } catch (error) {
        alertsFlowchart.innerHTML = '<div class="text-danger">Não foi possível atualizar o fluxograma.</div>';
        showToast(`Erro ao atualizar fluxograma: ${error.message}`, 'danger');
        return false;
    }
}

function renderAlertFlowchart(stats = {}, dashboard = {}) {
    if (!alertsFlowchart) return;
    const totalFlows = dashboard.total_flows || 0;
    const totalBytes = dashboard.total_bytes || 0;
    const interfaceCount = stats.interface_count || 0;
    const snmpErrors = stats.snmp_errors || 0;
    const activeRules = alertsCache.filter((rule) => rule.enabled).length;
    const queueLength = stats.queue_length || 0;
    const totalRules = alertsCache.length;
    const alertsLast24h = dashboard.alerts_last_24h || 0;
    const threatsBlocked = dashboard.threats_blocked || 0;

    const steps = [
        {
            icon: 'satellite-dish',
            title: 'Coleta de fluxos',
            metric: formatNumber(totalFlows),
            detail: totalBytes ? `${formatBytes(totalBytes)} nas últimas 24h` : 'Sem tráfego recente registrado',
        },
        {
            icon: 'network-wired',
            title: 'Enriquecimento SNMP',
            metric: `${formatNumber(interfaceCount)} interfaces`,
            detail: snmpErrors ? `${formatNumber(snmpErrors)} erros SNMP acumulados` : 'Nenhum erro SNMP reportado',
        },
        {
            icon: 'bell',
            title: 'Motor de regras',
            metric: `${formatNumber(activeRules)} ativas`,
            detail: `Fila: ${formatNumber(queueLength)} • Total de regras: ${formatNumber(totalRules)}`,
        },
        {
            icon: 'shield-halved',
            title: 'Ações e bloqueios',
            metric: `${formatNumber(alertsLast24h)} alertas`,
            detail: threatsBlocked ? `Bloqueios aplicados: ${formatNumber(threatsBlocked)}` : 'Nenhum bloqueio recente',
        },
    ];

    const pieces = [];
    steps.forEach((step, index) => {
        pieces.push(`
            <div class="alert-flow-step">
                <i class="fa-solid fa-${step.icon}"></i>
                <div class="text-uppercase small text-secondary mb-1">${step.title}</div>
                <div class="alert-flow-metric">${step.metric}</div>
                <div class="alert-flow-detail">${step.detail}</div>
            </div>
        `);
        if (index < steps.length - 1) {
            pieces.push('<div class="alert-flow-arrow d-none d-lg-flex"><i class="fa-solid fa-arrow-right-long"></i></div>');
        }
    });

    alertsFlowchart.innerHTML = pieces.join('');
}

alertsTable.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    const name = decodeURIComponent(button.dataset.name || '');
    if (!name) return;

        if (action === 'delete-alert') {
            if (!confirm(`Deseja remover a regra ${name}?`)) return;
            try {
                await apiFetch(`/api/alerts/${encodeURIComponent(name)}`, { method: 'DELETE' });
                showToast('Regra removida.', 'success');
                await loadAlerts();
                await loadAlertInsights();
            } catch (error) {
                showToast(`Falha ao remover: ${error.message}`, 'danger');
            }
        }

    if (action === 'edit-alert') {
        const current = alertsCache.find((item) => item.name === name);
        if (current) {
            openAlertModal(current);
            return;
        }
        try {
            const alerts = await apiFetch('/api/alerts');
            const fallback = alerts.find((item) => item.name === name);
            if (!fallback) {
                showToast('Regra não encontrada.', 'warning');
                return;
            }
            openAlertModal(fallback);
        } catch (error) {
            showToast(`Falha ao carregar regra: ${error.message}`, 'danger');
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
        actions: getSelectedAlertActions(),
        comment: document.getElementById('alert-comment').value.trim(),
        enabled: document.getElementById('alert-enabled').checked,
    };
    if (!payload.name) {
        alertFormFeedback.textContent = 'Informe um nome para a regra.';
        return;
    }
    alertFormFeedback.textContent = '';
    const submitBtn = alertForm.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        if (alertSubmitLabel) alertSubmitLabel.textContent = editingAlertName ? 'Salvando...' : 'Criando...';
    }
    try {
        if (editingAlertName) {
            await apiFetch(`/api/alerts/${encodeURIComponent(editingAlertName)}`, { method: 'PUT', json: payload });
            showToast('Regra atualizada.', 'success');
        } else {
            await apiFetch('/api/alerts', { method: 'POST', json: payload });
            showToast('Regra criada com sucesso.', 'success');
        }
        alertModal?.hide();
        await loadAlerts();
        await loadAlertInsights();
    } catch (error) {
        alertFormFeedback.textContent = error.message;
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            if (alertSubmitLabel) alertSubmitLabel.textContent = editingAlertName ? 'Salvar alterações' : 'Criar fluxo';
        }
    }
});

function renderConfigSummary(cfg = {}) {
    if (!configSummary) return;
    const cards = [
        {
            icon: 'network-wired',
            title: 'Fontes monitoradas',
            value: formatNumber((cfg.sources || []).length),
            detail: cfg.snmp_enabled ? 'SNMP habilitado' : 'SNMP desabilitado',
        },
        {
            icon: 'plug',
            title: 'Portas de ingestão',
            value: `NetFlow ${cfg.netflow_port || '-'} • sFlow ${cfg.sflow_port || '-'}`,
            detail: `API HTTP: ${cfg.http_port || '-'}`,
        },
        {
            icon: 'clock',
            title: 'Intervalos',
            value: `${cfg.update_interval_minutes || 0} min`,
            detail: `Limpeza ClickHouse: ${cfg.clickhouse_clean_time || 0} min`,
        },
        {
            icon: 'hdd',
            title: 'Armazenamento',
            value: cfg.maximum_disk_gb ? `${cfg.maximum_disk_gb} GB` : '-',
            detail: cfg.data_path || '-',
        },
    ];
    configSummary.innerHTML = cards
        .map(
            (card) => `
            <div class="col-md-6 col-xl-3">
                <div class="card h-100 bg-body-tertiary border-0">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <span class="text-secondary text-uppercase small">${card.title}</span>
                            <i class="fa-solid fa-${card.icon} text-primary"></i>
                        </div>
                        <p class="fs-4 fw-semibold mt-2 mb-1">${card.value}</p>
                        <p class="text-secondary mb-0">${card.detail}</p>
                    </div>
                </div>
            </div>`
        )
        .join('');
}

function fillConfigForm(cfg = {}) {
    if (!configControls.netflow) return;
    configControls.netflow.value = cfg.netflow_port ?? '';
    configControls.sflow.value = cfg.sflow_port ?? '';
    configControls.http.value = cfg.http_port ?? '';
    configControls.updateInterval.value = cfg.update_interval_minutes ?? '';
    configControls.cleanTime.value = cfg.clickhouse_clean_time ?? '';
    configControls.dataPath.value = cfg.data_path || '';
    configControls.maxDisk.value = cfg.maximum_disk_gb ?? '';
    configControls.password.value = '';
    configControls.apiNetwork.value = joinMultiline(cfg.api_network || []);
    configControls.internalBlocks.value = joinMultiline(cfg.internal_ip_blocks || []);
    configControls.internalASNs.value = joinMultiline((cfg.internal_asns || []).map(String));
    configControls.favoriteASNs.value = joinMultiline((cfg.favorite_asns || []).map(String));
    configControls.favoriteIPs.value = joinMultiline(cfg.favorite_ips || []);
    configControls.ignoredIPs.value = joinMultiline(cfg.ignored_ips || []);
    configControls.favoriteServices.value = joinMultiline(cfg.favorite_services || []);
    configControls.ignoredASNs.value = joinMultiline((cfg.ignored_asns || []).map(String));
    configControls.notificationApply.checked = false;

    const telegram = cfg.notification?.telegram || {};
    configControls.telegramEnabled.checked = Boolean(telegram.enabled);
    configControls.telegramBot.value = '';
    configControls.telegramProxy.value = telegram.proxy || '';
    configControls.telegramChatIDs.value = joinMultiline(telegram.chat_ids || []);
    configControls.telegramReplyIDs.value = joinMultiline(telegram.reply_ids || []);
    configControls.telegramAlerts.checked = Boolean(telegram.notify_alerts);
    configControls.telegramSystem.checked = Boolean(telegram.notify_system);

    const email = cfg.notification?.email || {};
    configControls.emailEnabled.checked = Boolean(email.enabled);
    configControls.emailHost.value = email.smtp_host || '';
    configControls.emailPort.value = email.smtp_port ?? '';
    configControls.emailFrom.value = email.from || '';
    configControls.emailUsername.value = email.username || '';
    configControls.emailPassword.value = '';
    configControls.emailTo.value = joinMultiline(email.to || []);
    configControls.emailReplyTo.value = joinMultiline(email.reply_to || []);
    configControls.emailTLS.checked = Boolean(email.use_tls);
    configControls.emailStartTLS.checked = Boolean(email.start_tls);

    const firewall = cfg.firewall || {};
    configControls.firewallNetflow.value = joinMultiline(firewall.netflow_allowed || []);
    configControls.firewallSflow.value = joinMultiline(firewall.sflow_allowed || []);
    configControls.firewallAPI.value = joinMultiline(firewall.api_allowed || []);
    configControls.firewallExport.value = joinMultiline(firewall.interface_export || []);
}

async function loadConfig() {
    try {
        const cfg = await apiFetch('/api/config');
        renderConfigSummary(cfg);
        fillConfigForm(cfg);
    } catch (error) {
        showToast(`Erro ao carregar configuração: ${error.message}`, 'danger');
    }
}

document.getElementById('reload-config').addEventListener('click', loadConfig);

configForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {};
    const netflow = Number(configControls.netflow.value);
    if (Number.isFinite(netflow)) payload.netflow_port = netflow;
    const sflow = Number(configControls.sflow.value);
    if (Number.isFinite(sflow)) payload.sflow_port = sflow;
    const httpPort = Number(configControls.http.value);
    if (Number.isFinite(httpPort)) payload.http_port = httpPort;
    const updateInterval = Number(configControls.updateInterval.value);
    if (Number.isFinite(updateInterval)) payload.update_interval_minutes = updateInterval;
    const cleanTime = Number(configControls.cleanTime.value);
    if (Number.isFinite(cleanTime)) payload.clickhouse_clean_time = cleanTime;
    const maxDisk = Number(configControls.maxDisk.value);
    if (Number.isFinite(maxDisk)) payload.maximum_disk_gb = maxDisk;
    if (configControls.dataPath.value.trim()) payload.data_path = configControls.dataPath.value.trim();
    if (configControls.password.value.trim()) payload.password = configControls.password.value.trim();

    payload.api_network = splitList(configControls.apiNetwork.value);
    payload.internal_ip_blocks = splitList(configControls.internalBlocks.value);
    payload.internal_asns = splitList(configControls.internalASNs.value, true);
    payload.favorite_asns = splitList(configControls.favoriteASNs.value, true);
    payload.favorite_ips = splitList(configControls.favoriteIPs.value);
    payload.ignored_ips = splitList(configControls.ignoredIPs.value);
    payload.favorite_services = splitList(configControls.favoriteServices.value);
    payload.ignored_asns = splitList(configControls.ignoredASNs.value, true);

    if (configControls.notificationApply.checked) {
        const telegram = {
            enabled: configControls.telegramEnabled.checked,
            proxy: configControls.telegramProxy.value.trim(),
            chat_ids: splitList(configControls.telegramChatIDs.value),
            reply_ids: splitList(configControls.telegramReplyIDs.value),
            notify_alerts: configControls.telegramAlerts.checked,
            notify_system: configControls.telegramSystem.checked,
        };
        const botToken = configControls.telegramBot.value.trim();
        if (botToken) telegram.bot_token = botToken;

        const email = {
            enabled: configControls.emailEnabled.checked,
            smtp_host: configControls.emailHost.value.trim(),
            smtp_port: Number(configControls.emailPort.value) || 0,
            username: configControls.emailUsername.value.trim(),
            from: configControls.emailFrom.value.trim(),
            to: splitList(configControls.emailTo.value),
            reply_to: splitList(configControls.emailReplyTo.value),
            use_tls: configControls.emailTLS.checked,
            start_tls: configControls.emailStartTLS.checked,
        };
        const emailPassword = configControls.emailPassword.value.trim();
        if (emailPassword) email.password = emailPassword;
        if (!email.smtp_host) delete email.smtp_host;
        if (!email.from) delete email.from;
        if (!Number.isFinite(email.smtp_port) || email.smtp_port <= 0) delete email.smtp_port;

        payload.notification = {
            telegram,
            email,
        };
    }

    const firewall = {
        netflow_allowed: splitList(configControls.firewallNetflow.value),
        sflow_allowed: splitList(configControls.firewallSflow.value),
        api_allowed: splitList(configControls.firewallAPI.value),
        interface_export: splitList(configControls.firewallExport.value),
    };
    if (
        firewall.netflow_allowed.length ||
        firewall.sflow_allowed.length ||
        firewall.api_allowed.length ||
        firewall.interface_export.length
    ) {
        payload.firewall = firewall;
    }

    const submitBtn = configForm.querySelector('button[type="submit"]');
    configFormFeedback.textContent = '';
    configFormFeedback.classList.remove('text-danger');
    if (submitBtn) submitBtn.disabled = true;
    try {
        await apiFetch('/api/config', { method: 'PUT', json: payload });
        showToast('Configuração atualizada.', 'success');
        configControls.notificationApply.checked = false;
        configFormFeedback.textContent = 'Parâmetros atualizados com sucesso.';
        await loadConfig();
    } catch (error) {
        configFormFeedback.textContent = error.message;
        configFormFeedback.classList.add('text-danger');
    } finally {
        if (submitBtn) submitBtn.disabled = false;
    }
});

function renderWhitelistCurrent(ips = [], cidrs = []) {
    if (!whitelistCurrent) return;
    const badges = [];
    ips.forEach((ip) => badges.push(`<span class="badge bg-success-subtle text-success-emphasis border border-success-subtle">${ip}</span>`));
    cidrs.forEach((cidr) => badges.push(`<span class="badge bg-info-subtle text-info-emphasis border border-info-subtle">${cidr}</span>`));
    whitelistCurrent.innerHTML = badges.length
        ? badges.join(' ')
        : '<span class="text-secondary">Nenhuma entrada cadastrada.</span>';
}

async function loadWhitelist() {
    try {
        const data = await apiFetch('/api/whitelist');
        const ips = Array.isArray(data?.ips) ? data.ips : [];
        const cidrs = Array.isArray(data?.cidrs) ? data.cidrs : [];
        whitelistIPsInput.value = joinMultiline(ips);
        whitelistCIDRsInput.value = joinMultiline(cidrs);
        renderWhitelistCurrent(ips, cidrs);
        whitelistFeedback.textContent = '';
        whitelistFeedback.classList.remove('text-danger');
    } catch (error) {
        showToast(`Erro ao carregar whitelist: ${error.message}`, 'danger');
    }
}

reloadWhitelistBtn?.addEventListener('click', loadWhitelist);

whitelistForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
        ips: splitList(whitelistIPsInput.value),
        cidrs: splitList(whitelistCIDRsInput.value),
    };
    whitelistFeedback.textContent = '';
    whitelistFeedback.classList.remove('text-danger');
    try {
        await apiFetch('/api/whitelist', { method: 'PUT', json: payload });
        whitelistFeedback.textContent = 'Whitelist salva com sucesso.';
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
    ['#tab-routers', async () => {
        await loadRouters();
        await loadRouterSummary();
        await loadBGPPeers();
    }],
    ['#tab-alerts', async () => {
        await loadAlerts();
        await loadAlertInsights();
    }],
    ['#tab-config', loadConfig],
    ['#tab-whitelist', async () => { await loadWhitelist(); await loadFirewallStatus(); }],
    ['#tab-management', async () => { await loadGrafana(); await loadBGPPeers(); }],
    ['#tab-data', async () => { await loadInterfaces(); await loadFlows(); }],
]);

document.getElementById('app-tabs').addEventListener('shown.bs.tab', async (event) => {
    const target = event.target.getAttribute('data-bs-target');
    const loader = tabLoaders.get(target);
    if (loader) {
        try {
            await loader();
        } catch (error) {
            showToast(`Falha ao atualizar aba: ${error.message}`, 'danger');
        }
    }
});

checkSession();
