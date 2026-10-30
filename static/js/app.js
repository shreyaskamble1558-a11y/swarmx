(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const state = {
    dashboard: null, incidents: [], events: [], alerts: [], agents: [], agentRuns: [],
    reports: [], settings: null, selectedIncident: null, charts: {}, network: null,
    networkFrame: null, eventPage: 1, eventTotal: 0, eventTypes: [],
    incidentPage: 1, incidentTotal: 0, alertPage: 1, alertTotal: 0,
    networkTransform: { scale: 1, x: 0, y: 0 },
    selectedNetworkNode: null, networkDragging: null
  };
  let refreshTimer;
  let lastFocusedElement = null;
  const filterTimers = {};
  const severityColors = { Critical: "#ff687d", High: "#ffb65c", Medium: "#e6cb72", Low: "#55c9a6" };

  async function api(url, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      const headers = new Headers(options.headers || {});
      headers.set("X-CSRF-Token", document.querySelector('meta[name="csrf-token"]')?.content || "");
      options = { ...options, headers };
    }
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.success === false) {
      throw new Error(data.error?.message || data.error || `Request failed (${response.status})`);
    }
    if (data.success === true && Object.hasOwn(data, "data")) {
      if (data.meta && Number.isFinite(data.meta.total)) {
        if (url.startsWith("/api/v1/events")) state.eventTotal = data.meta.total;
        if (url.startsWith("/api/v1/incidents")) state.incidentTotal = data.meta.total;
        if (url.startsWith("/api/v1/alerts")) state.alertTotal = data.meta.total;
      }
      return data.data;
    }
    return data;
  }

  async function apiV1(path, options = {}) {
    return api(`/api/v1${path}`, options);
  }

  function listUrl(resource, page, filters) {
    const params = new URLSearchParams({ page: String(page), limit: "50" });
    Object.entries(filters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    return `/${resource}?${params.toString()}`;
  }

  function queueFilterLoad(key, pageKey, loader, immediate = false) {
    state[pageKey] = 1;
    clearTimeout(filterTimers[key]);
    if (immediate) {
      loader().catch(error => toast(error.message, true));
      return;
    }
    filterTimers[key] = setTimeout(() => loader().catch(error => toast(error.message, true)), 250);
  }

  function uploadFile(form, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/v1/events/upload");
      xhr.setRequestHeader("X-CSRF-Token", document.querySelector('meta[name="csrf-token"]')?.content || "");
      xhr.upload.addEventListener("progress", event => {
        if (event.lengthComputable) onProgress(Math.round(event.loaded * 100 / event.total));
      });
      xhr.addEventListener("load", () => {
        let payload;
        try { payload = JSON.parse(xhr.responseText); } catch { reject(new Error("The server returned an unreadable response.")); return; }
        if (xhr.status < 200 || xhr.status >= 300 || payload.success === false) {
          reject(new Error(payload.error?.message || payload.error || `Upload failed (${xhr.status})`));
          return;
        }
        resolve(payload.success === true ? payload.data : payload);
      });
      xhr.addEventListener("error", () => reject(new Error("Upload connection failed.")));
      xhr.addEventListener("abort", () => reject(new Error("Upload was cancelled.")));
      xhr.send(new FormData(form));
    });
  }

  function toast(message, error = false) {
    const el = $("#toast");
    el.textContent = message;
    el.classList.toggle("error", error);
    el.classList.add("show");
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => el.classList.remove("show"), 3600);
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[char]));
  }

  function severityBadge(value) {
    return `<span class="severity-badge severity-${String(value).toLowerCase()}">${escapeHtml(value)}</span>`;
  }

  function statusBadge(value) {
    return `<span class="status-badge status-${String(value).toLowerCase()}">${escapeHtml(value)}</span>`;
  }

  function shortDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function renderIncidents() {
    const all = state.incidents;
    $("#incident-rows").innerHTML = all.map(item => `
      <tr><td><button class="table-link" data-open-incident="${item.id}">${escapeHtml(item.incident_uid || `INC-${String(item.id).padStart(4, "0")}`)} · ${escapeHtml(item.title)}</button></td>
      <td>${severityBadge(item.severity)}</td><td>${statusBadge(item.status)}</td><td class="mono">${escapeHtml(item.source_ip || "—")}</td>
      <td class="mono">${shortDate(item.created_at)}</td><td class="mono">${item.alert_count || 0}</td><td><button class="text-button" data-open-incident="${item.id}">DETAILS ↗</button></td></tr>`).join("");
    $("#incidents-empty").classList.toggle("visible", all.length === 0);
    $("#incident-page-info").textContent = `${state.incidentTotal.toLocaleString()} incidents · page ${state.incidentPage}`;
    $("#incident-prev").disabled = state.incidentPage <= 1;
    $("#incident-next").disabled = state.incidentPage * 50 >= state.incidentTotal;
    const recent = state.dashboard?.recent_incidents || [];
    $("#recent-incidents").innerHTML = recent.map(item => `
      <tr><td><button class="table-link" data-open-incident="${item.id}">INC-${String(item.id).padStart(4, "0")} · ${escapeHtml(item.title)}</button></td>
      <td>${severityBadge(item.severity)}</td><td>${statusBadge(item.status)}</td>
      <td class="mono">${escapeHtml(item.source_ip || "—")}</td><td class="mono">${item.alert_count || 0}</td></tr>`).join("");
    $("#recent-empty").classList.toggle("visible", recent.length === 0);
    $("#nav-incident-count").textContent = String(state.dashboard?.metrics.open_incidents || 0);
    const options = all.map(item => `<option value="${item.id}">${escapeHtml(item.incident_uid || `INC-${item.id}`)} · ${escapeHtml(item.title)}</option>`).join("");
    ["#agent-incident-select", "#report-incident-select"].forEach(selector => {
      const select = $(selector);
      if (!select) return;
      const selected = select.value;
      select.innerHTML = options || '<option value="">No incidents available</option>';
      if (all.some(item => String(item.id) === selected)) select.value = selected;
    });
    const networkIncident = $("#network-incident");
    if (networkIncident) {
      const selected = networkIncident.value;
      networkIncident.innerHTML = '<option value="">All incidents</option>' +
        all.map(item => `<option value="${item.id}">${escapeHtml(item.incident_uid || item.id)}</option>`).join("");
      if (all.some(item => String(item.id) === selected)) networkIncident.value = selected;
    }
  }

  function renderEvents() {
    $("#event-rows").innerHTML = state.events.map(item => {
      const topSeverity = ["Critical", "High", "Medium", "Low"].find(level =>
        (item.alert_severities || "").split(",").includes(level));
      return `
      <tr data-event-id="${item.id}"><td><button class="table-link" data-open-event="${item.id}">${shortDate(item.timestamp)}</button></td><td class="mono">${escapeHtml(item.source_ip)}</td>
      <td class="mono">${escapeHtml(item.dest_ip || "—")}</td><td>${escapeHtml(item.event_type)}</td>
      <td>${escapeHtml(item.username || "—")}</td><td>${escapeHtml(item.action || "—")}</td>
      <td>${item.alert_count ? `<span class="severity-badge severity-${(topSeverity || "Low").toLowerCase()}">${item.alert_count} alert${item.alert_count === 1 ? "" : "s"}</span>` : '<span class="mono">—</span>'}</td></tr>`;
    }).join("");
    $("#events-empty").classList.toggle("visible", state.events.length === 0);
    const typeSelect = $("#event-type-filter");
    if (typeSelect) {
      const selected = typeSelect.value;
      const types = state.eventTypes;
      typeSelect.innerHTML = '<option value="">All types</option>' +
        types.map(type => `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`).join("");
      typeSelect.value = types.includes(selected) ? selected : "";
    }
    $("#event-page-info").textContent = `${state.eventTotal.toLocaleString()} events · page ${state.eventPage}`;
    $("#event-prev").disabled = state.eventPage <= 1;
    $("#event-next").disabled = state.eventPage * 50 >= state.eventTotal;
  }

  function renderAlerts() {
    $("#alert-rows").innerHTML = state.alerts.map(alert => `<tr>
      <td><button class="table-link" data-open-alert="${alert.id}">ALT-${String(alert.id).padStart(5, "0")} · ${escapeHtml(alert.title)}</button></td>
      <td>${severityBadge(alert.severity)}</td><td class="mono">${escapeHtml(alert.rule_id)}</td>
      <td class="mono">${escapeHtml(alert.source_ip || "—")}</td><td class="mono">${shortDate(alert.timestamp)}</td>
      <td>${statusBadge(alert.status || "New")}</td><td><button class="table-link" data-open-incident="${alert.incident_id}">${escapeHtml(alert.incident_uid || "Open")}</button></td>
      <td>${alert.status === "New" ? `<button class="text-button" data-alert-action="acknowledge" data-alert-id="${alert.id}">ACK</button>` : ""}
      ${alert.status === "Acknowledged" ? `<button class="text-button" data-alert-action="investigate" data-alert-id="${alert.id}">INVESTIGATE</button>` : ""}</td>
      </tr>`).join("");
    $("#alerts-empty").classList.toggle("visible", state.alerts.length === 0);
    $("#alert-page-info").textContent = `${state.alertTotal.toLocaleString()} alerts · page ${state.alertPage}`;
    $("#alert-prev").disabled = state.alertPage <= 1;
    $("#alert-next").disabled = state.alertPage * 50 >= state.alertTotal;
  }

  function renderInsights(data) {
    const metrics = data.metrics;
    $("#metric-processed").textContent = metrics.events_processed.toLocaleString();
    $("#metric-investigating").textContent = metrics.investigating_incidents.toLocaleString();
    $("#metric-resolved").textContent = metrics.resolved_incidents.toLocaleString();
    $("#metric-rules").textContent = metrics.active_rules.toLocaleString();
    $("#metric-jobs").textContent = metrics.analysis_jobs_completed.toLocaleString();
    $("#metric-failures").textContent = metrics.ingestion_failures.toLocaleString();
    $("#recent-alert-list").innerHTML = data.recent_alerts.map(alert => `<div class="compact-row">
      <span>${severityBadge(alert.severity)} <strong>${escapeHtml(alert.title)}</strong></span>
      <small>${escapeHtml(alert.incident_uid)} · ${shortDate(alert.created_at)}</small></div>`).join("") ||
      '<div class="table-empty visible">No alerts recorded.</div>';
    $("#top-source-list").innerHTML = data.top_sources.map(item => `<div class="compact-row">
      <span class="mono">${escapeHtml(item.source_ip)}</span><strong>${item.count} events</strong></div>`).join("") ||
      '<div class="mono">No source records.</div>';
    $("#top-rule-list").innerHTML = data.top_rules.map(item => `<div class="compact-row">
      <span class="mono">${escapeHtml(item.rule_id)}</span><strong>${item.count} alerts</strong></div>`).join("") ||
      '<div class="mono">No rules triggered.</div>';
    $("#status-distribution").innerHTML = data.status_distribution.map(item =>
      `<div class="compact-row">${statusBadge(item.status)}<strong>${item.count}</strong></div>`).join("") ||
      '<div class="mono">No incidents.</div>';
    $("#recent-action-list").innerHTML = data.recent_actions.map(item =>
      `<div class="compact-row"><span>${escapeHtml(item.action)}</span><small>${shortDate(item.created_at)}</small></div>`).join("") ||
      '<div class="mono">No analyst actions.</div>';
    $("#dashboard-agent-list").innerHTML = data.agent_status.map(item =>
      `<div class="compact-row"><span class="mono">${escapeHtml(item.agent_id)}</span>${statusBadge(item.status)}</div>`).join("") ||
      '<div class="mono">No completed agent executions.</div>';
  }

  function renderAgents() {
    const grid = $("#agent-grid");
    if (!grid) return;
    grid.innerHTML = state.agents.map(agent => {
      const run = agent.latest_run;
      return `<article class="panel agent-tile"><div class="agent-tile-top"><span class="metric-icon cyan">✳</span>${statusBadge(agent.state || "Idle")}</div>
        <h2>${escapeHtml(agent.name)}</h2><p>${escapeHtml(agent.responsibility)}</p>
        <div class="agent-run-meta">Latest execution: ${run?.completed_at ? shortDate(run.completed_at) : "No runs yet"}</div>
        ${run?.error ? `<div class="form-message">${escapeHtml(run.error)}</div>` : ""}</article>`;
    }).join("");
    $("#agent-run-list").innerHTML = state.agentRuns.map(run => `<div class="run-row">
      <span class="mono">${escapeHtml(run.job_uid)}</span><span>${escapeHtml(run.summary || run.status)}</span>
      ${statusBadge(run.status)}<span class="mono">${shortDate(run.completed_at || run.started_at)}</span></div>`).join("") ||
      '<div class="table-empty visible">No agent executions yet.</div>';
  }

  async function loadReports() {
    state.reports = await apiV1("/reports?limit=50");
    const list = $("#report-list");
    if (!list) return;
    list.innerHTML = state.reports.map(report => `<div class="report-row">
      <span><strong>${escapeHtml(report.report_uid)}</strong><small>${escapeHtml(report.incident_id ? `Incident ${report.incident_id}` : "Incident removed")} · ${shortDate(report.created_at)}</small></span>
      <a class="button button-secondary" href="/api/v1/reports/${report.id}/download?format=json">JSON</a>
      <a class="button button-secondary" href="/api/v1/reports/${report.id}/download?format=html">Print HTML</a></div>`).join("");
    $("#reports-empty").classList.toggle("visible", state.reports.length === 0);
  }

  async function loadSettings() {
    state.settings = await apiV1("/settings");
    const settings = state.settings.settings;
    $("#settings-fields").innerHTML = `
      <label class="setting-field">Max events per import<input id="setting-max-events" type="number" min="1" max="100000" value="${escapeHtml(settings.max_events_per_import)}"></label>
      <label class="setting-field">Dashboard refresh (seconds)<input id="setting-refresh" type="number" min="5" max="300" value="${escapeHtml(settings.dashboard_refresh_seconds)}"></label>
      <label class="setting-check"><input id="setting-dedupe" type="checkbox" ${settings.deduplicate_events === "true" ? "checked" : ""}> Deduplicate identical events</label>
      <p class="agent-run-meta">Records are retained indefinitely; automatic retention and deletion are not enabled.</p>
      <div class="agent-run-meta">Analysis mode: local deterministic · SQLite ${escapeHtml(state.settings.database_status)} · ${state.settings.event_count} events stored</div>`;
    $("#rule-settings").innerHTML = state.settings.rules.map(rule => `<label class="setting-check">
      <input type="checkbox" data-rule-id="${escapeHtml(rule.rule_id)}" ${rule.enabled ? "checked" : ""}>
      <span><strong>${escapeHtml(rule.name)}</strong><small>${escapeHtml(rule.description)}</small></span></label>`).join("");
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(() => refresh().catch(markDisconnected),
      Number(settings.dashboard_refresh_seconds || 30) * 1000);
  }

  function markDisconnected(error) {
    $("#connection-status").innerHTML = '<span class="offline-dot"></span> API DISCONNECTED';
    ["#metric-events", "#metric-alerts", "#metric-open", "#metric-critical", "#metric-processed",
      "#metric-investigating", "#metric-resolved", "#metric-rules", "#metric-jobs", "#metric-failures"]
      .forEach(selector => { if ($(selector)) $(selector).textContent = "—"; });
    $("#last-updated").textContent = "DATA UNAVAILABLE";
    if (error) toast(`Backend connection failed: ${error.message}`, true);
  }

  function updateChart(key, canvas, type, data, options) {
    if (!window.Chart || !canvas) return;
    if (state.charts[key]) state.charts[key].destroy();
    state.charts[key] = new Chart(canvas, { type, data, options });
  }

  function renderCharts(data) {
    const activityLabels = data.activity.map(item => item.day);
    $("#activity-empty").classList.toggle("visible", data.metrics.events === 0 || !window.Chart);
    $("#activity-empty").textContent = window.Chart
      ? "Ingest an event file to begin visualizing activity."
      : "Chart library unavailable; telemetry data remains stored.";
    $("#severity-empty").classList.toggle("visible", !window.Chart);
    updateChart("activity", $("#activity-chart"), "line", {
      labels: activityLabels,
      datasets: [{ data: data.activity.map(item => item.count), borderColor: "#48d9e8", backgroundColor: ctx => {
        const gradient = ctx.chart.ctx.createLinearGradient(0, 0, 0, 190);
        gradient.addColorStop(0, "#48d9e833"); gradient.addColorStop(1, "#48d9e800"); return gradient;
      }, fill: true, tension: .38, pointRadius: 3, pointHoverRadius: 5, pointBackgroundColor: "#48d9e8", borderWidth: 2 }]
    }, { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { backgroundColor: "#172438", titleColor: "#dbe7f2", bodyColor: "#a9bbcc", borderColor: "#354b61", borderWidth: 1 } },
      scales: { x: { grid: { display: false }, ticks: { color: "#708197", maxTicksLimit: 7, font: { size: 9 } }, border: { display: false } },
        y: { beginAtZero: true, grid: { color: "#1e2a3b" }, ticks: { color: "#708197", precision: 0, font: { size: 9 } }, border: { display: false } } } });
    const names = ["Critical", "High", "Medium", "Low"];
    const counts = Object.fromEntries(data.severity.map(item => [item.severity, item.count]));
    const values = names.map(name => counts[name] || 0);
    const total = values.reduce((sum, value) => sum + value, 0);
    $("#severity-total").textContent = String(total);
    $("#severity-legend").innerHTML = names.map(name => `<div class="legend-row"><i class="legend-dot" style="background:${severityColors[name]}"></i><span>${name}</span><strong class="legend-count">${counts[name] || 0}</strong></div>`).join("");
    updateChart("severity", $("#severity-chart"), "doughnut", { labels: names, datasets: [{ data: values, backgroundColor: names.map(name => severityColors[name]), borderColor: "#101a29", borderWidth: 4, hoverOffset: 4 }] },
      { responsive: true, maintainAspectRatio: false, cutout: "76%", plugins: { legend: { display: false }, tooltip: { backgroundColor: "#172438", borderColor: "#354b61", borderWidth: 1, padding: 9 } } });
  }

  function renderNetwork(data) {
    const canvas = $("#network-canvas"), ctx = canvas.getContext("2d");
    if (state.networkFrame) cancelAnimationFrame(state.networkFrame);
    state.networkFrame = null;
    const bounds = canvas.getBoundingClientRect(), ratio = window.devicePixelRatio || 1;
    canvas.width = Math.max(bounds.width, 1) * ratio; canvas.height = Math.max(bounds.height, 1) * ratio;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    const width = bounds.width, height = bounds.height;
    $("#network-empty").style.display = data.nodes.length ? "none" : "grid";
    $("#network-stats").textContent = `${data.nodes.length} hosts · ${data.links.length} observed relationships`;
    if (!data.nodes.length || !width || !height) {
      state.network = null;
      ctx.clearRect(0, 0, width, height);
      return;
    }
    const positions = new Map(), nodes = data.nodes;
    nodes.forEach((node, index) => {
      const angle = (Math.PI * 2 * index / nodes.length) - Math.PI / 2;
      const radiusX = Math.min(width * .35, 390), radiusY = Math.min(height * .32, 190);
      positions.set(node.id, { x: width / 2 + Math.cos(angle) * radiusX, y: height / 2 + Math.sin(angle) * radiusY });
    });
    state.network = { data, positions, width, height, startedAt: performance.now() };
    const draw = now => {
      const graph = state.network;
      if (!graph) return;
      ctx.clearRect(0, 0, graph.width, graph.height);
      ctx.save();
      ctx.translate(state.networkTransform.x, state.networkTransform.y);
      ctx.scale(state.networkTransform.scale, state.networkTransform.scale);
      ctx.lineWidth = 1;
      graph.data.links.forEach((link, index) => {
        const source = graph.positions.get(link.source), target = graph.positions.get(link.target);
        if (!source || !target) return;
        ctx.beginPath(); ctx.moveTo(source.x, source.y); ctx.lineTo(target.x, target.y);
        ctx.strokeStyle = "#7890a52a"; ctx.stroke();
        const midX = (source.x + target.x) / 2, midY = (source.y + target.y) / 2;
        ctx.fillStyle = "#65798d"; ctx.font = "9px DM Mono, monospace";
        if (link.count > 1) ctx.fillText(String(link.count), midX + 4, midY - 4);
        const phase = ((now - graph.startedAt) / 2600 + index / graph.data.links.length) % 1;
        ctx.beginPath();
        ctx.arc(source.x + (target.x - source.x) * phase,
          source.y + (target.y - source.y) * phase, 2, 0, Math.PI * 2);
        ctx.fillStyle = "#70e8ed"; ctx.shadowColor = "#48d9e8"; ctx.shadowBlur = 9; ctx.fill();
        ctx.shadowBlur = 0;
      });
      graph.data.nodes.forEach(node => {
        const point = graph.positions.get(node.id), color = node.kind === "source" ? "#48d9e8" : "#a68cff";
        const pulse = Math.sin(now / 550 + node.events) * .65;
        ctx.beginPath(); ctx.arc(point.x, point.y, 5 + Math.min(node.events, 12) * .45 + pulse, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.shadowColor = color; ctx.shadowBlur = 14; ctx.fill(); ctx.shadowBlur = 0;
        ctx.fillStyle = "#b7c6d5"; ctx.font = "10px DM Mono, monospace";
        ctx.fillText(node.id, point.x + 12, point.y + 4);
        if (node.id === state.selectedNetworkNode) {
          ctx.beginPath(); ctx.arc(point.x, point.y, 15, 0, Math.PI * 2);
          ctx.strokeStyle = "#e6f7ff"; ctx.lineWidth = 1; ctx.stroke();
        }
      });
      ctx.restore();
      state.networkFrame = requestAnimationFrame(draw);
    };
    state.networkFrame = requestAnimationFrame(draw);
    $("#relationship-list").innerHTML = data.links.map((link, index) => `<button class="relationship-row" data-open-edge="${index}">
      <span class="mono">${escapeHtml(link.source)} → ${escapeHtml(link.target)}</span>
      <span>${escapeHtml(link.event_type)}</span><small>${link.count} event(s) · ${shortDate(link.last_seen)}</small></button>`).join("") ||
      '<span class="mono">No observed relationships.</span>';
  }

  async function loadNetwork() {
    const params = new URLSearchParams();
    if ($("#network-severity").value) params.set("severity", $("#network-severity").value);
    if ($("#network-incident").value) params.set("incident_id", $("#network-incident").value);
    const hours = Number($("#network-time-range").value || 0);
    if (hours) params.set("start", new Date(Date.now() - hours * 60 * 60 * 1000).toISOString());
    const data = await apiV1(`/network/graph?${params.toString()}`);
    state.networkData = data;
    renderNetwork(data);
  }

  async function loadIncidents() {
    const filters = {
      q: $("#incident-search").value,
      status: $("#status-filter").value,
      severity: $("#incident-severity-filter").value
    };
    state.incidents = await apiV1(listUrl("incidents", state.incidentPage, filters));
    renderIncidents();
  }

  async function loadEvents() {
    const filters = {
      q: $("#event-search").value,
      event_type: $("#event-type-filter").value,
      severity: $("#event-severity-filter").value
    };
    state.events = await apiV1(listUrl("events", state.eventPage, filters));
    renderEvents();
  }

  async function loadAlerts() {
    const filters = {
      q: $("#alert-search").value,
      severity: $("#alert-severity-filter").value,
      status: $("#alert-status-filter").value
    };
    state.alerts = await apiV1(listUrl("alerts", state.alertPage, filters));
    renderAlerts();
  }

  async function refresh() {
    const [dashboard, incidents, events, alerts, agents, runs, network, eventTypes] = await Promise.all([
      api("/api/dashboard"),
      apiV1(listUrl("incidents", state.incidentPage, {
        q: $("#incident-search").value, status: $("#status-filter").value,
        severity: $("#incident-severity-filter").value
      })),
      apiV1(listUrl("events", state.eventPage, {
        q: $("#event-search").value, event_type: $("#event-type-filter").value,
        severity: $("#event-severity-filter").value
      })),
      apiV1(listUrl("alerts", state.alertPage, {
        q: $("#alert-search").value, severity: $("#alert-severity-filter").value,
        status: $("#alert-status-filter").value
      })),
      apiV1("/agents"), apiV1("/agents/runs?limit=10"), api("/api/network"), apiV1("/events/types")
    ]);
    state.dashboard = dashboard; state.incidents = incidents; state.events = events;
    state.alerts = alerts; state.agents = agents; state.agentRuns = runs; state.networkData = network;
    state.eventTypes = eventTypes;
    $("#metric-events").textContent = dashboard.metrics.events.toLocaleString();
    $("#metric-alerts").textContent = dashboard.metrics.alerts.toLocaleString();
    $("#metric-open").textContent = dashboard.metrics.open_incidents.toLocaleString();
    $("#metric-critical").textContent = dashboard.metrics.critical_incidents.toLocaleString();
    $("#last-updated").textContent = `UPDATED ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    $("#connection-status").innerHTML = '<span class="green-dot"></span> SYSTEM OPERATIONAL';
    renderInsights(dashboard); renderIncidents(); renderEvents(); renderAlerts(); renderAgents();
    renderCharts(dashboard); renderNetwork(network);
  }

  function navigate(view, updateHistory = true) {
    const known = ["overview", "incidents", "events", "alerts", "agents", "network", "reports", "settings"].includes(view) ? view : "overview";
    if (known !== "network" && state.networkFrame) {
      cancelAnimationFrame(state.networkFrame);
      state.networkFrame = null;
    }
    $$(".view-section").forEach(section => section.classList.toggle("active", section.id === `view-${known}`));
    $$(".nav-link").forEach(link => {
      const active = link.dataset.view === known;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    $("#sidebar").classList.remove("mobile-open");
    $("#mobile-nav-toggle").setAttribute("aria-expanded", "false");
    $("#mobile-nav-toggle").setAttribute("aria-label", "Open navigation");
    $("#current-section").textContent = known.charAt(0).toUpperCase() + known.slice(1);
    if (updateHistory && location.hash !== `#${known}`) {
      history.pushState(null, "", `#${known}`);
    }
    if (known === "network") api("/api/network").then(data => {
      state.networkData = data; renderNetwork(data);
    }).catch(error => toast(error.message, true));
    if (known === "reports") loadReports().catch(error => toast(error.message, true));
    if (known === "settings") loadSettings().catch(error => toast(error.message, true));
  }

  function openModal(id) {
    const modal = $(`#${id}`);
    lastFocusedElement = document.activeElement;
    modal.classList.add("open"); modal.setAttribute("aria-hidden", "false");
    modal.querySelector("[data-close-modal]")?.focus();
  }

  function closeModal(button) {
    const modal = button?.closest(".modal-backdrop") || button;
    if (modal?.classList.contains("modal-backdrop")) {
      modal.classList.remove("open"); modal.setAttribute("aria-hidden", "true");
      if (lastFocusedElement?.isConnected) lastFocusedElement.focus();
      lastFocusedElement = null;
    }
  }

  async function openIncident(id) {
    try {
      const data = await apiV1(`/incidents/${id}`);
      state.selectedIncident = data.incident;
      const incident = data.incident;
      $("#detail-content").innerHTML = `
        <div class="detail-header"><div class="eyebrow"><span class="eyebrow-line"></span> INCIDENT ${escapeHtml(incident.incident_uid || `INC-${String(incident.id).padStart(4, "0")}`)}</div>
        <h2 class="detail-title" id="detail-title">${escapeHtml(incident.title)}</h2><div class="detail-meta">${severityBadge(incident.severity)} ${statusBadge(incident.status)} <span class="mono">${escapeHtml(incident.source_ip || "Unknown source")}</span></div></div>
        <p class="detail-summary">${escapeHtml(incident.summary)} · Confidence ${Math.round((incident.confidence || 0) * 100)}% (triage score, not a calibrated probability).</p>
        <div class="detail-selects"><label>SEVERITY<select id="detail-severity">${["Low", "Medium", "High", "Critical"].map(value => `<option ${incident.severity === value ? "selected" : ""}>${value}</option>`).join("")}</select></label>
        <label>STATUS<select id="detail-status">${["New", "Open", "Investigating", "Contained", "Resolved", "Closed"].map(value => `<option ${incident.status === value ? "selected" : ""}>${value}</option>`).join("")}</select></label>
        <label>ASSIGNED ANALYST<input id="detail-assignee" maxlength="100" value="${escapeHtml(incident.assigned_analyst || "")}" placeholder="Unassigned"></label>
        <button class="button button-secondary" id="save-incident" style="align-self:end">Save changes</button></div>
        <label class="setting-field">Severity override rationale<textarea id="detail-rationale" maxlength="500" placeholder="Required only when changing severity"></textarea></label>
        <p class="mono">Severity basis: ${escapeHtml(incident.severity_rationale || "Not recorded.")}</p>
        <div class="detail-section-title">LINKED ALERTS · ${data.alerts.length}</div>
        ${data.alerts.length ? data.alerts.map(alert => `<div class="alert-card"><strong>${escapeHtml(alert.title)} ${severityBadge(alert.severity)}</strong><p>${escapeHtml(alert.description)} · <span class="evidence-ref">events:${escapeHtml(alert.event_ids || alert.event_id)}</span></p><p class="mono" style="margin-top:5px">${shortDate(alert.timestamp)} · ${escapeHtml(alert.event_type)} · ${escapeHtml(alert.source_ip)}</p></div>`).join("") : '<div class="table-empty visible">No linked alerts.</div>'}
        <div class="detail-section-title">LOCAL MULTI-AGENT TRIAGE</div><div id="agent-results"><p class="mono">Run analysis to generate evidence-linked advisory findings.</p></div>
        <div class="detail-actions"><button class="button button-primary" id="run-analysis">✳ Run agent analysis</button><button class="button button-secondary" id="generate-selected-report">Generate report</button></div>
        <div class="detail-section-title">ANALYST NOTES · ${data.notes.length}</div><div id="notes-list">${data.notes.map(note => `<div class="note-item"><div class="note-time">${shortDate(note.created_at)} · ${escapeHtml(note.author || "Local analyst")}</div><p>${escapeHtml(note.text)}</p></div>`).join("") || '<p class="mono">No notes added yet.</p>'}</div>
        <form class="note-form" id="note-form"><textarea name="text" maxlength="2000" placeholder="Add a case note…" required></textarea><button class="button button-secondary" type="submit">Add note</button></form>
        <div class="detail-section-title">STATUS HISTORY</div>${data.history.map(item => `<div class="note-item"><div class="note-time">${shortDate(item.created_at)}</div><p>${escapeHtml(item.field)}: ${escapeHtml(item.old_value)} → ${escapeHtml(item.new_value)}${item.rationale ? ` · ${escapeHtml(item.rationale)}` : ""}</p></div>`).join("") || '<p class="mono">No changes recorded.</p>'}
        <p class="mono">Agent output is advisory only. Human review is required; SwarmX does not execute response actions.</p>`;
      openModal("detail-modal");
    } catch (error) { toast(error.message, true); }
  }

  async function openEvent(id) {
    try {
      const event = await apiV1(`/events/${id}`);
      $("#detail-content").innerHTML = `<div class="eyebrow"><span class="eyebrow-line"></span> NORMALIZED EVENT</div>
        <h2 class="detail-title" id="detail-title">Event ${escapeHtml(event.event_uid || event.id)}</h2>
        <p class="detail-summary">${shortDate(event.timestamp)} · ${escapeHtml(event.source_ip)} → ${escapeHtml(event.dest_ip || "No destination")}</p>
        <div class="detail-section-title">NORMALIZED FIELDS</div><pre class="raw-record">${escapeHtml(JSON.stringify({
          event_type: event.event_type, source_ip: event.source_ip, dest_ip: event.dest_ip,
          source_port: event.source_port, dest_port: event.dest_port, protocol: event.protocol,
          username: event.username, hostname: event.hostname, action: event.action,
          result: event.result, message: event.message, source_file: event.source_file,
          is_synthetic: Boolean(event.is_synthetic)
        }, null, 2))}</pre>
        <div class="detail-section-title">ORIGINAL SOURCE RECORD</div><pre class="raw-record">${escapeHtml(event.raw_json)}</pre>
        <div class="detail-section-title">RELATED ALERTS</div>${event.alerts.map(alert =>
          `<div class="alert-card"><strong>${escapeHtml(alert.title)} ${severityBadge(alert.severity)}</strong><p>${escapeHtml(alert.rule_id)} · ${escapeHtml(alert.incident_uid)}</p></div>`
        ).join("") || '<p class="mono">No alert linked to this event.</p>'}`;
      openModal("detail-modal");
    } catch (error) { toast(error.message, true); }
  }

  async function openAlert(id) {
    try {
      const alert = await apiV1(`/alerts/${id}`);
      $("#detail-content").innerHTML = `<div class="eyebrow"><span class="eyebrow-line"></span> DETECTION ALERT</div>
        <h2 class="detail-title" id="detail-title">${escapeHtml(alert.title)}</h2>
        <div class="detail-meta">${severityBadge(alert.severity)} ${statusBadge(alert.status)} <span class="mono">${escapeHtml(alert.rule_id)}</span></div>
        <p class="detail-summary">${escapeHtml(alert.description)}</p>
        <div class="detail-section-title">EVIDENCE</div><pre class="raw-record">${escapeHtml(JSON.stringify({
          summary: JSON.parse(alert.evidence || "{}"),
          matching_conditions: JSON.parse(alert.matching_conditions || "{}"),
          rationale: alert.rationale,
          event_ids: JSON.parse(alert.event_ids || "[]")
        }, null, 2))}</pre>
        <p class="mono">${shortDate(alert.timestamp)} · ${escapeHtml(alert.source_ip)} → ${escapeHtml(alert.dest_ip || "No destination")} · ${escapeHtml(alert.incident_uid)}</p>
        <div class="detail-actions"><button class="button button-secondary" data-open-event="${alert.event_id}">Open source event</button>
        <button class="button button-secondary" data-open-incident="${alert.incident_id}">Open incident</button>
        ${alert.status === "New" ? `<button class="button button-primary" data-alert-action="acknowledge" data-alert-id="${alert.id}">Acknowledge</button>` : ""}
        ${alert.status === "Acknowledged" ? `<button class="button button-primary" data-alert-action="investigate" data-alert-id="${alert.id}">Investigate</button>` : ""}</div>`;
      openModal("detail-modal");
    } catch (error) { toast(error.message, true); }
  }

  document.addEventListener("click", async event => {
    const target = event.target.closest("button") || event.target;
    const nav = event.target.closest("[data-view]");
    if (nav) { event.preventDefault(); navigate(nav.dataset.view); return; }
    if (target.id === "mobile-nav-toggle") {
      const open = $("#sidebar").classList.toggle("mobile-open");
      target.setAttribute("aria-expanded", String(open));
      target.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
      return;
    }
    const route = event.target.closest("[data-navigate]");
    if (route) { navigate(route.dataset.navigate); return; }
    const incident = event.target.closest("[data-open-incident]");
    if (incident) { openIncident(incident.dataset.openIncident); return; }
    const alertLink = event.target.closest("[data-open-alert]");
    if (alertLink) { openAlert(alertLink.dataset.openAlert); return; }
    const eventLink = event.target.closest("[data-open-event]");
    if (eventLink) { openEvent(eventLink.dataset.openEvent); return; }
    const close = event.target.closest("[data-close-modal]");
    if (close) { closeModal(close); return; }
    if (event.target.classList.contains("modal-backdrop")) { closeModal(event.target.querySelector("[data-close-modal]")); return; }
    if (target.id === "ingest-open" || target.id === "events-ingest") { openModal("ingest-modal"); return; }
    if (target.id === "refresh-button") {
      try { await refresh(); toast("Dashboard refreshed."); } catch (error) { markDisconnected(error); }
      return;
    }
    if (target.id === "load-demo") {
      const button = target; button.disabled = true;
      try {
        const result = await apiV1(`/demo/scenarios/${$("#scenario-select").value}/run`, { method: "POST" });
        await refresh(); toast(`Synthetic scenario loaded · ${result.accepted} new event(s), ${result.alerts_created} alert(s), ${result.analysis_runs.length} analysis job(s).`);
      } catch (error) { toast(error.message, true); } finally { button.disabled = false; }
      return;
    }
    if (target.id === "events-export" || target.id === "incident-export") {
      window.location.href = "/api/export/events.csv"; return;
    }
    if (target.id === "save-incident") {
      try {
        const body = {
          severity: $("#detail-severity").value,
          status: $("#detail-status").value,
          assigned_analyst: $("#detail-assignee").value
        };
        if (body.severity !== state.selectedIncident.severity) body.rationale = $("#detail-rationale").value;
        const updated = await apiV1(`/incidents/${state.selectedIncident.id}`, {
          method: "PATCH", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        });
        toast("Incident updated."); await refresh(); await openIncident(updated.id);
      } catch (error) { toast(error.message, true); }
      return;
    }
    if (target.id === "run-analysis") {
      const button = target; button.disabled = true; button.textContent = "Analyzing…";
      try {
        const report = await apiV1(`/incidents/${state.selectedIncident.id}/analyze`, { method: "POST" });
        $("#agent-results").innerHTML = `<p class="mono">${escapeHtml(report.assessment)} · Human review required: ${report.human_review_required ? "yes" : "no"}.</p>` +
          report.agent_findings.map(item => `<div class="agent-result"><strong><span class="agent-name">${escapeHtml(item.agent)}</span> ${item.validated ? '<span class="evidence-ref">· EVIDENCE VALIDATED</span>' : '<span class="severity-badge severity-medium">UNVERIFIED</span>'}</strong><p>${escapeHtml(item.finding)}<br><span class="evidence-ref">${item.evidence.map(escapeHtml).join(" · ") || "No supporting alert references"}</span></p></div>`).join("");
        toast(`Analysis ${report.job_status} · ${report.validation_status}.`); await refresh();
      } catch (error) { toast(error.message, true); } finally { button.disabled = false; button.textContent = "✳ Run agent analysis"; }
      return;
    }
    if (target.dataset.alertAction) {
      try {
        await apiV1(`/alerts/${target.dataset.alertId}/${target.dataset.alertAction}`, { method: "POST" });
        toast("Alert state saved."); await refresh();
        if ($("#detail-modal").classList.contains("open")) await openAlert(target.dataset.alertId);
      } catch (error) { toast(error.message, true); }
      return;
    }
    if (target.id === "run-fleet-analysis") {
      const incidentId = $("#agent-incident-select").value;
      if (!incidentId) { toast("Select an incident before running analysis.", true); return; }
      target.disabled = true;
      try {
        const result = await apiV1("/agents/analyze", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ incident_id: incidentId }) });
        await refresh(); toast(`Analysis ${result.job_status} · ${result.validation_status}.`);
      } catch (error) { toast(error.message, true); } finally { target.disabled = false; }
      return;
    }
    if (target.id === "agents-refresh") {
      try { await refresh(); toast("Agent execution data refreshed."); } catch (error) { toast(error.message, true); }
      return;
    }
    if (target.id === "generate-report" || target.id === "generate-selected-report") {
      const incidentId = target.id === "generate-report" ? $("#report-incident-select").value : state.selectedIncident?.id;
      if (!incidentId) { toast("Select an incident before generating a report.", true); return; }
      try {
        const result = await apiV1("/reports/generate", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ incident_id: incidentId }) });
        if (target.id === "generate-report") $("#report-message").textContent = `${result.report_id} generated.`;
        navigate("reports"); await loadReports(); toast("Incident report generated.");
      } catch (error) { toast(error.message, true); }
      return;
    }
    if (target.id === "save-settings") {
      try {
        await apiV1("/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
          max_events_per_import: $("#setting-max-events").value,
          dashboard_refresh_seconds: $("#setting-refresh").value,
          deduplicate_events: $("#setting-dedupe").checked
        }) });
        toast("Workspace settings saved."); await loadSettings();
      } catch (error) { toast(error.message, true); }
      return;
    }
    if (target.id === "save-rules") {
      const detection_rules = Object.fromEntries($$("#rule-settings [data-rule-id]").map(input => [input.dataset.ruleId, input.checked]));
      try {
        await apiV1("/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ detection_rules }) });
        toast("Detection rules updated."); await refresh(); await loadSettings();
      } catch (error) { toast(error.message, true); }
      return;
    }
    if (target.id === "reset-demo") {
      if (!window.confirm("Remove synthetic demonstration events and their isolated cases? Imported event data will be preserved.")) return;
      try {
        const result = await apiV1("/demo/scenarios", { method: "DELETE", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ confirm: true }) });
        await refresh(); toast(`Removed ${result.events_removed} synthetic event(s).`);
      } catch (error) { toast(error.message, true); }
      return;
    }
    if (target.id === "network-reset") {
      state.networkTransform = { scale: 1, x: 0, y: 0 };
      state.selectedNetworkNode = null;
      if (state.networkData) renderNetwork(state.networkData);
      return;
    }
    const edgeLink = event.target.closest("[data-open-edge]");
    if (edgeLink && state.networkData) {
      const link = state.networkData.links[Number(edgeLink.dataset.openEdge)];
      if (link) toast(`${link.source} → ${link.target} · ${link.event_type} · ${link.count} observed event(s)`);
      return;
    }
    const paginationActions = {
      "incident-prev": ["incidentPage", -1, loadIncidents], "incident-next": ["incidentPage", 1, loadIncidents],
      "event-prev": ["eventPage", -1, loadEvents], "event-next": ["eventPage", 1, loadEvents],
      "alert-prev": ["alertPage", -1, loadAlerts], "alert-next": ["alertPage", 1, loadAlerts]
    };
    if (paginationActions[target.id]) {
      const [pageKey, delta, loader] = paginationActions[target.id];
      const previousPage = state[pageKey];
      state[pageKey] = Math.max(1, previousPage + delta);
      try { await loader(); }
      catch (error) { state[pageKey] = previousPage; toast(error.message, true); }
      return;
    }
  });

  document.addEventListener("keydown", event => {
    const modal = $(".modal-backdrop.open");
    if (!modal) return;
    if (event.key === "Escape") {
      event.preventDefault();
      closeModal(modal);
      return;
    }
    if (event.key === "Tab") {
      const focusable = [...modal.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')]
        .filter(element => element.getClientRects().length);
      if (!focusable.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first.focus();
      }
    }
  });

  window.addEventListener("popstate", () => navigate(location.hash.slice(1) || "overview", false));

  document.addEventListener("submit", async event => {
    if (event.target.id === "ingest-form") {
      event.preventDefault();
      const file = $("#event-file").files[0];
      if (!file) return;
      if (file.size > 5 * 1024 * 1024) { $("#ingest-message").textContent = "File exceeds the 5 MB upload limit."; return; }
      const button = $("#ingest-submit"), message = $("#ingest-message");
      const progress = $("#upload-progress");
      button.disabled = true; button.textContent = "Validating…"; message.classList.remove("success"); message.textContent = "";
      progress.hidden = false; progress.value = 0;
      try {
        const result = await uploadFile(event.target, value => { progress.value = value; });
        message.classList.add("success");
        message.textContent = `${result.accepted} accepted · ${result.rejected} rejected · ${result.duplicates} duplicate(s) skipped · ${result.alerts_created} alert(s).`;
        await refresh();
        if (result.rejected) toast(`${result.rejected} invalid row(s) were skipped.`, true);
        else toast("Event file ingested successfully.");
        setTimeout(() => { $("#ingest-modal").classList.remove("open"); $("#ingest-modal").setAttribute("aria-hidden", "true"); event.target.reset(); $("#file-name").textContent = "Choose a CSV or JSON file"; }, 1200);
      } catch (error) { message.textContent = error.message; }
      finally { button.disabled = false; button.textContent = "Validate & ingest"; progress.hidden = true; }
    }
    if (event.target.id === "note-form") {
      event.preventDefault();
      try {
        const text = new FormData(event.target).get("text");
        await apiV1(`/incidents/${state.selectedIncident.id}/notes`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text })
        });
        toast("Analyst note added."); await openIncident(state.selectedIncident.id); await refresh();
      } catch (error) { toast(error.message, true); }
    }
  });

  $("#event-file").addEventListener("change", event => {
    $("#file-name").textContent = event.target.files[0]?.name || "Choose a CSV or JSON file";
  });
  $("#incident-search").addEventListener("input", () => queueFilterLoad("incidents", "incidentPage", loadIncidents));
  $("#status-filter").addEventListener("change", () => queueFilterLoad("incidents", "incidentPage", loadIncidents, true));
  $("#incident-severity-filter").addEventListener("change", () => queueFilterLoad("incidents", "incidentPage", loadIncidents, true));
  $("#event-search").addEventListener("input", () => queueFilterLoad("events", "eventPage", loadEvents));
  $("#event-type-filter").addEventListener("change", () => queueFilterLoad("events", "eventPage", loadEvents, true));
  $("#event-severity-filter").addEventListener("change", () => queueFilterLoad("events", "eventPage", loadEvents, true));
  $("#alert-search").addEventListener("input", () => queueFilterLoad("alerts", "alertPage", loadAlerts));
  $("#alert-severity-filter").addEventListener("change", () => queueFilterLoad("alerts", "alertPage", loadAlerts, true));
  $("#alert-status-filter").addEventListener("change", () => queueFilterLoad("alerts", "alertPage", loadAlerts, true));
  $("#network-canvas").addEventListener("click", event => {
    if (!state.network) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const transform = state.networkTransform;
    const x = (event.clientX - rect.left - transform.x) / transform.scale;
    const y = (event.clientY - rect.top - transform.y) / transform.scale;
    for (const node of state.network.data.nodes) {
      const point = state.network.positions.get(node.id);
      if (Math.hypot(point.x - x, point.y - y) < 20) {
        state.selectedNetworkNode = node.id;
        renderNetwork(state.networkData);
        toast(`${node.kind.toUpperCase()} · ${node.id} · ${node.events} event(s)`);
        return;
      }
    }
    for (const link of state.network.data.links) {
      const start = state.network.positions.get(link.source), end = state.network.positions.get(link.target);
      const dx = end.x - start.x, dy = end.y - start.y;
      const lengthSquared = dx * dx + dy * dy || 1;
      const projection = Math.max(0, Math.min(1, ((x - start.x) * dx + (y - start.y) * dy) / lengthSquared));
      if (Math.hypot(x - (start.x + projection * dx), y - (start.y + projection * dy)) < 7) {
        toast(`${link.source} → ${link.target} · ${link.event_type} · ${link.count} observed event(s)`);
        return;
      }
    }
  });
  $("#network-canvas").addEventListener("pointerdown", event => {
    state.networkDragging = { x: event.clientX, y: event.clientY };
    event.currentTarget.setPointerCapture(event.pointerId);
  });
  $("#network-canvas").addEventListener("pointermove", event => {
    if (!state.networkDragging) return;
    state.networkTransform.x += event.clientX - state.networkDragging.x;
    state.networkTransform.y += event.clientY - state.networkDragging.y;
    state.networkDragging = { x: event.clientX, y: event.clientY };
    renderNetwork(state.networkData);
  });
  ["pointerup", "pointercancel"].forEach(type =>
    $("#network-canvas").addEventListener(type, () => { state.networkDragging = null; }));
  $("#network-canvas").addEventListener("wheel", event => {
    event.preventDefault();
    const scale = state.networkTransform.scale * (event.deltaY < 0 ? 1.1 : 0.9);
    state.networkTransform.scale = Math.max(.5, Math.min(3, scale));
    renderNetwork(state.networkData);
  }, { passive: false });
  $("#network-severity").addEventListener("change", () => loadNetwork().catch(error => toast(error.message, true)));
  $("#network-incident").addEventListener("change", () => loadNetwork().catch(error => toast(error.message, true)));
  $("#network-time-range").addEventListener("change", () => loadNetwork().catch(error => toast(error.message, true)));
  const uploadZone = $("#upload-zone");
  ["dragenter", "dragover"].forEach(type => uploadZone.addEventListener(type, event => {
    event.preventDefault(); uploadZone.classList.add("drag-active");
  }));
  ["dragleave", "drop"].forEach(type => uploadZone.addEventListener(type, event => {
    event.preventDefault(); uploadZone.classList.remove("drag-active");
  }));
  uploadZone.addEventListener("drop", event => {
    const file = event.dataTransfer.files[0];
    if (!file) return;
    const transfer = new DataTransfer(); transfer.items.add(file);
    $("#event-file").files = transfer.files;
    $("#file-name").textContent = file.name;
  });
  window.addEventListener("resize", () => { if (state.network) renderNetwork(state.network.data); });
  navigate(location.hash.slice(1) || "overview", false);
  refresh().catch(markDisconnected);
  refreshTimer = setInterval(() => refresh().catch(markDisconnected), 30000);
})();
