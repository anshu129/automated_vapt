const API = "/api/v1";

const state = {
  scanId: null,
  jobPollers: {},
  activeTab: "overview",
  cache: {},
  assessmentState: null,
  jobStatus: null,
};

function setStatusBadge(el, status) {
  if (!el) return;
  const label = status || "—";
  el.textContent = label;
  el.className = "badge " + (status || "");
}

async function loadAssessmentState(jobStatus) {
  if (!state.scanId) return null;
  const qs = jobStatus ? `?job_status=${encodeURIComponent(jobStatus)}` : "";
  const data = await api(`/scans/${state.scanId}/assessment-state${qs}`);
  state.assessmentState = data;
  if (jobStatus) state.jobStatus = jobStatus;
  return data;
}

function renderStatusBadges() {
  const jobBadge = document.getElementById("jobStatusBadge");
  const assessBadge = document.getElementById("assessmentStatusBadge");
  const jobStatus = state.jobStatus || state.assessmentState?.job_status || "—";
  const assessmentStatus =
    state.assessmentState?.assessment_status || state.assessmentState?.status || "—";
  setStatusBadge(jobBadge, jobStatus);
  setStatusBadge(assessBadge, assessmentStatus);
}

/* ---------- helpers ---------- */
function scanCredentials() {
  const username = document.getElementById("usernameInput")?.value.trim() || null;
  const password = document.getElementById("passwordInput")?.value || null;
  return { username: username || null, password: password || null };
}

function showError(title, message, detail) {
  document.getElementById("errorTitle").textContent = title || "Error";
  const body = document.getElementById("errorBody");
  body.innerHTML = "";
  body.appendChild(h("p", {}, esc(message)));
  if (detail) {
    body.appendChild(h("div", { class: "error-detail" }, esc(detail)));
  }
  document.getElementById("errorOverlay").classList.remove("hidden");
}

function closeError() {
  document.getElementById("errorOverlay").classList.add("hidden");
}

async function api(path, opts = {}, { popupOnError = false } = {}) {
  try {
    const res = await fetch(API + path, {
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        detail = body.detail || body.message || detail;
        if (typeof detail !== "string") detail = JSON.stringify(detail);
      } catch (_) {}
      const err = new Error(`${res.status}: ${detail}`);
      if (popupOnError) showError("Request failed", err.message);
      throw err;
    }
    return res.json();
  } catch (err) {
    if (popupOnError && !(err.message || "").match(/^\d{3}:/)) {
      showError("Network error", err.message || "Could not reach the API");
    }
    throw err;
  }
}

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function")
      node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
  );
}

function toast(msg, isErr = false) {
  if (isErr) {
    showError("Something went wrong", msg);
    return;
  }
  const t = h("div", { class: "toast" }, msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

function panel(name) {
  return document.querySelector(`.panel[data-panel="${name}"]`);
}

function openModal(title, node) {
  document.getElementById("modalTitle").textContent = title;
  const body = document.getElementById("modalBody");
  body.innerHTML = "";
  body.appendChild(node);
  document.getElementById("modalOverlay").classList.remove("hidden");
}
function closeModal() {
  document.getElementById("modalOverlay").classList.add("hidden");
}

function detailRow(k, v) {
  return h("div", { class: "detail-row" }, h("div", { class: "k" }, k), h("div", {}, v ?? "—"));
}

async function assetMap() {
  const data = await cached("assets", () => api(`/scans/${state.scanId}/assets`));
  const map = {};
  data.items.forEach((a) => (map[a.id] = a));
  return map;
}
function assetLabel(map, id) {
  const a = map[id];
  return a ? `${a.asset_type}: ${a.display_name || a.normalized_key}` : id;
}

/* ---------- boot ---------- */
async function checkApi() {
  const badge = document.getElementById("apiStatus");
  try {
    await fetch("/health");
    badge.textContent = "API online";
    badge.className = "topbar-status ok";
  } catch (_) {
    badge.textContent = "API offline";
    badge.className = "topbar-status err";
  }
}

async function loadScanHistory() {
  const box = document.getElementById("scanHistory");
  try {
    const data = await api("/ui/scans");
    if (!data.items.length) {
      box.innerHTML = '<p class="muted">No scans yet.</p>';
      return;
    }
    box.innerHTML = "";
    data.items.slice(0, 25).forEach((s) => {
      box.appendChild(
        h(
          "div",
          { class: "history-item", onclick: () => openScan(s.id) },
          h("div", { class: "h-title" }, s.name || s.id.slice(0, 8)),
          h(
            "div",
            { class: "muted" },
            `${s.scan_status || s.status}${s.assessment_status ? " · assess " + s.assessment_status : ""} · ${s.created_at ? new Date(s.created_at).toLocaleString() : ""}`
          )
        )
      );
    });
  } catch (e) {
    box.innerHTML = `<p class="muted">${esc(e.message)}</p>`;
  }
}

function renderJobs() {
  const box = document.getElementById("jobsList");
  const jobs = Object.values(state.jobPollers).map((p) => p.data).filter(Boolean);
  if (!jobs.length) {
    box.innerHTML = '<p class="muted">No active jobs.</p>';
    return;
  }
  box.innerHTML = "";
  jobs
    .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""))
    .forEach((j) => {
      box.appendChild(
        h(
          "div",
          { class: "job", onclick: () => openScan(j.scan_id) },
          h(
            "div",
            { class: "job-title" },
            j.name || j.target,
            " ",
            h("span", { class: "badge " + j.status }, j.status)
          ),
          h("div", { class: "job-phase" }, `${j.phase} · ${j.elapsed_seconds || 0}s`)
        )
      );
    });
}

function pollJob(jobId) {
  if (state.jobPollers[jobId]) return;
  const poller = { data: null, timer: null };
  state.jobPollers[jobId] = poller;
  const tick = async () => {
    try {
      const job = await api(`/ui/jobs/${jobId}`);
      poller.data = job;
      renderJobs();
      if (state.scanId === job.scan_id) updateProgress(job);
      if (job.status === "COMPLETED" || job.status === "FAILED") {
        clearInterval(poller.timer);
        if (job.status === "COMPLETED") {
          toast(`Scan completed for ${job.target}`);
          if (state.scanId === job.scan_id) refreshCurrent();
          loadScanHistory();
        } else {
          const msg = `Scan failed: ${job.error || "unknown"}`;
          toast(msg, true);
        }
      }
    } catch (e) {
      clearInterval(poller.timer);
      showError("Job polling failed", e.message);
    }
  };
  poller.timer = setInterval(tick, 2500);
  tick();
}

function updateProgress(job) {
  const bar = document.getElementById("progressBar");
  const fill = document.getElementById("progressFill");
  const label = document.getElementById("progressLabel");
  const phases = ["queued", "reconnaissance", "planning", "ai_validation", "tool_validation", "completed"];
  if (job.status === "COMPLETED" || job.status === "FAILED") {
    bar.classList.add("hidden");
  } else {
    bar.classList.remove("hidden");
    const idx = Math.max(0, phases.indexOf(job.phase));
    fill.style.width = `${(idx / (phases.length - 1)) * 100}%`;
    label.textContent = `${job.phase} · ${job.elapsed_seconds || 0}s / budget ${job.time_budget_minutes}m`;
  }
  state.jobStatus = job.status;
  if (job.assessment_status) {
    state.assessmentState = state.assessmentState || {};
    state.assessmentState.assessment_status = job.assessment_status;
    state.assessmentState.job_status = job.status;
  }
  renderStatusBadges();
}

/* ---------- scan launch ---------- */
async function startScan(e) {
  e.preventDefault();
  const host = document.getElementById("hostInput").value.trim();
  if (!host) return;
  const btn = document.getElementById("startBtn");
  btn.disabled = true;
  btn.textContent = "Starting…";
  try {
    const creds = scanCredentials();
    const job = await api("/ui/scans", {
      method: "POST",
      body: JSON.stringify({
        host,
        name: document.getElementById("nameInput").value.trim() || null,
        run_ai: document.getElementById("aiInput").checked,
        run_mcp: document.getElementById("mcpInput").checked,
        run_mcp_active: document.getElementById("mcpActiveInput").checked,
        time_budget_minutes: parseInt(document.getElementById("budgetInput").value || "30", 10),
        username: creds.username,
        password: creds.password,
      }),
    });
    toast(`Assessment queued for ${job.target}`);
    pollJob(job.job_id);
    openScan(job.scan_id);
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Start assessment";
  }
}

/* ---------- scan view ---------- */
async function openScan(scanId) {
  state.scanId = scanId;
  state.cache = {};
  state.assessmentState = null;
  state.jobStatus = null;
  document.getElementById("emptyState").classList.add("hidden");
  document.getElementById("scanView").classList.remove("hidden");
  selectTab(state.activeTab || "overview");
  try {
    const scan = await api(`/scans/${scanId}`);
    document.getElementById("scanTitle").textContent = scan.name || scanId;
    const assess = scan.assessment_completion?.assessment_status || scan.assessment_status;
    document.getElementById("scanMeta").textContent =
      `Scan ${scanId} · lifecycle ${scan.scan_status || scan.status}` +
      (assess ? ` · assessment ${assess}` : "");
    state.assessmentState = scan.assessment_completion || null;
    state.jobStatus = scan.job_status || null;
    if (!state.assessmentState) {
      await loadAssessmentState(state.jobStatus);
    }
    renderStatusBadges();
  } catch (e) {
    toast(e.message, true);
  }
}

function refreshCurrent() {
  state.cache = {};
  if (state.scanId) {
    openScan(state.scanId);
  }
}

function selectTab(name) {
  state.activeTab = name;
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.tab === name)
  );
  document.querySelectorAll(".panel").forEach((p) =>
    p.classList.toggle("active", p.dataset.panel === name)
  );
  loadTab(name);
}

async function loadTab(name) {
  const p = panel(name);
  if (!p) return;
  p.innerHTML = '<p class="empty-note">Loading…</p>';
  try {
    const loaders = {
      overview: loadOverview,
      assets: loadAssets,
      graph: loadGraph,
      vulns: loadVulns,
      hypotheses: loadHypotheses,
      validation: loadValidation,
      mcp: loadMcpValidation,
      ai: loadAI,
    };
    await loaders[name](p);
  } catch (e) {
    p.innerHTML = `<p class="empty-note">${esc(e.message)}</p>`;
    showError("Failed to load tab", e.message);
  }
}

async function cached(key, fn) {
  if (!state.cache[key]) state.cache[key] = await fn();
  return state.cache[key];
}

function statBox(num, lbl, cls = "") {
  return h(
    "div",
    { class: "stat" },
    h("div", { class: "num " + cls }, String(num)),
    h("div", { class: "lbl" }, lbl)
  );
}

/* ---------- tab loaders ---------- */
async function loadOverview(p) {
  const id = state.scanId;
  const [assets, rels, applic, hyps, backlog, findings, completion] = await Promise.all([
    api(`/scans/${id}/assets`),
    api(`/scans/${id}/relationships`),
    api(`/scans/${id}/vulnerability-applicability`),
    api(`/scans/${id}/hypotheses`),
    api(`/scans/${id}/validation-backlog`),
    api(`/scans/${id}/confirmed-findings`),
    cached("completion", () => api(`/scans/${id}/assessment-state`)),
  ]);
  state.assessmentState = completion;
  renderStatusBadges();
  const applicable = applic.items.filter((i) => i.state === "APPLICABLE").length;
  const summary = completion.summary || {};
  const pending = completion.pending_work_summary || completion.pending_work || {};
  const pendingTotal = pending.total ?? 0;
  const acceptedCount = Object.values(completion.accepted_gaps || {}).reduce(
    (n, v) => n + (Array.isArray(v) ? v.length : 0),
    0
  );
  p.innerHTML = "";
  p.appendChild(
    h("div", { class: "completion-card" },
      h("h3", {}, summary.headline || "Assessment state"),
      h("p", { class: "muted" }, summary.one_line_reason || completion.completion_notes || "—"),
      h("div", { class: "completion-reasons" },
        ...(completion.reason_codes || []).map((code) =>
          h("span", { class: "reason-chip" }, code)
        )
      ),
      h("p", {},
        `Pending work: ${pendingTotal} · Accepted gaps: ${acceptedCount}` +
        (completion.bound_reached ? ` · Bound reached: ${completion.bound_reached}` : "")
      ),
      completion.evaluation_timestamp
        ? h("p", { class: "muted" }, `Last evaluated: ${new Date(completion.evaluation_timestamp).toLocaleString()}`)
        : null,
      completion.latest_transition
        ? h(
            "p",
            { class: "muted" },
            `Latest transition: ${completion.latest_transition.previous_status || "—"} → ${completion.latest_transition.new_status}`
          )
        : null,
      completion.latest_report_snapshot
        ? h(
            "p",
            { class: "muted" },
            `Report: ${completion.latest_report_snapshot.report_version} · hash ${completion.latest_report_snapshot.content_hash.slice(0, 12)}` +
              (completion.latest_report_snapshot.replayable ? " · snapshot-backed" : "") +
              (completion.latest_report_snapshot.artifact_storage_backend
                ? ` · ${completion.latest_report_snapshot.artifact_storage_backend}`
                : "") +
              (completion.latest_report_snapshot.freshness_status === "STALE" ||
              completion.latest_report_snapshot.is_stale
                ? " · stale"
                : completion.latest_report_snapshot.freshness_status === "UNKNOWN"
                  ? " · unknown"
                  : " · fresh") +
              (completion.latest_report_snapshot.integrity_status &&
              completion.latest_report_snapshot.integrity_status !== "OK"
                ? ` · integrity:${completion.latest_report_snapshot.integrity_status}`
                : "")
          )
        : null
    )
  );
  p.appendChild(
    h(
      "div",
      { class: "stat-grid" },
      statBox(assets.total, "Assets", "accent"),
      statBox(rels.total, "Relationships"),
      statBox(applic.total, "Applicability cells"),
      statBox(applicable, "Applicable", "warn"),
      statBox(hyps.total, "Hypotheses"),
      statBox(backlog.items.length, "Validation tasks", "accent"),
      statBox(findings.total, "Confirmed findings", findings.total ? "bad" : "good")
    )
  );
  const history = completion.history || [];
  if (history.length) {
    p.appendChild(h("div", { class: "section-title" }, "Assessment status history"));
    const list = h("div", { class: "history-list-compact" });
    history.slice(0, 15).forEach((row) => {
      list.appendChild(
        h("div", { class: "history-row" },
          h("span", {}, row.created_at ? new Date(row.created_at).toLocaleString() : "—"),
          h("span", {}, `${row.previous_status || "—"} → ${row.new_status}`),
          h("span", { class: "muted" }, (row.reason_codes || []).join(", ") || row.triggered_by || "")
        )
      );
    });
    p.appendChild(list);
  }
  p.appendChild(
    h(
      "div",
      { class: "note" },
      "AI and automated checks are advisory. Findings are confirmed only after evidence is recorded through the validation workflow — nothing here is auto-confirmed."
    )
  );
  p.appendChild(h("div", { class: "section-title" }, "Assets by type"));
  const byType = {};
  assets.items.forEach((a) => (byType[a.asset_type] = (byType[a.asset_type] || 0) + 1));
  const tbl = h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Type"), h("th", {}, "Count"))));
  const body = h("tbody");
  Object.entries(byType).forEach(([t, c]) =>
    body.appendChild(h("tr", {}, h("td", {}, t), h("td", {}, String(c))))
  );
  tbl.appendChild(body);
  p.appendChild(byType && Object.keys(byType).length ? tbl : h("p", { class: "empty-note" }, "No assets discovered yet."));
}

async function loadAssets(p) {
  const data = await cached("assets", () => api(`/scans/${state.scanId}/assets`));
  if (!data.items.length) return void (p.innerHTML = '<p class="empty-note">No assets discovered.</p>');
  const body = h("tbody");
  data.items.forEach((a) => {
    const meta = a.metadata || {};
    const tech = (meta.technologies || []).join(", ");
    body.appendChild(
      h(
        "tr",
        {},
        h("td", {}, h("span", { class: "pill mode" }, a.asset_type)),
        h("td", {}, a.display_name || a.normalized_key),
        h("td", { class: "mono" }, a.normalized_key),
        h("td", {}, tech || "—"),
        h("td", {}, a.confidence != null ? a.confidence.toFixed(2) : "—")
      )
    );
  });
  p.innerHTML = "";
  p.appendChild(
    h(
      "table",
      {},
      h("thead", {}, h("tr", {}, h("th", {}, "Type"), h("th", {}, "Name"), h("th", {}, "Key"), h("th", {}, "Technologies"), h("th", {}, "Conf."))),
      body
    )
  );
}

async function loadGraph(p) {
  const [assets, rels] = await Promise.all([
    cached("assets", () => api(`/scans/${state.scanId}/assets`)),
    cached("rels", () => api(`/scans/${state.scanId}/relationships`)),
  ]);
  p.innerHTML = "";
  if (!assets.items.length) return void (p.innerHTML = '<p class="empty-note">No assets to graph.</p>');
  const colors = {
    WEB_APPLICATION: "#4f8cff",
    ENDPOINT: "#7c5cff",
    HOSTNAME: "#35c98a",
    DOMAIN: "#35c98a",
    IP_ADDRESS: "#f2b53c",
    SERVICE: "#46b6d9",
    DEFAULT: "#8a97ad",
  };
  const legend = h("div", { class: "graph-legend" });
  [...new Set(assets.items.map((a) => a.asset_type))].forEach((t) => {
    legend.appendChild(
      h("span", {}, h("span", { class: "legend-dot", style: `background:${colors[t] || colors.DEFAULT}` }), t)
    );
  });

  const W = 900, H = 520, cx = W / 2, cy = H / 2;
  const nodes = assets.items.slice(0, 80);
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const pos = new Map();
  nodes.forEach((n, i) => {
    const ang = (i / nodes.length) * Math.PI * 2;
    const r = 60 + Math.min(200, nodes.length * 3);
    pos.set(n.id, { x: cx + r * Math.cos(ang), y: cy + r * Math.sin(ang) });
  });
  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", "520");

  rels.items.forEach((r) => {
    const a = pos.get(r.source_asset_id), b = pos.get(r.target_asset_id);
    if (!a || !b) return;
    const line = document.createElementNS(svgNS, "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("stroke", "#2b3550"); line.setAttribute("stroke-width", "1");
    svg.appendChild(line);
  });
  nodes.forEach((n) => {
    const pt = pos.get(n.id);
    const g = document.createElementNS(svgNS, "g");
    const c = document.createElementNS(svgNS, "circle");
    c.setAttribute("cx", pt.x); c.setAttribute("cy", pt.y); c.setAttribute("r", "8");
    c.setAttribute("fill", colors[n.asset_type] || colors.DEFAULT);
    const title = document.createElementNS(svgNS, "title");
    title.textContent = `${n.asset_type}: ${n.display_name || n.normalized_key}`;
    c.appendChild(title);
    const label = document.createElementNS(svgNS, "text");
    label.setAttribute("x", pt.x + 11); label.setAttribute("y", pt.y + 4);
    label.setAttribute("fill", "#8a97ad"); label.setAttribute("font-size", "10");
    label.textContent = (n.display_name || n.normalized_key || "").slice(0, 26);
    g.appendChild(c); g.appendChild(label);
    svg.appendChild(g);
  });

  const wrap = h("div", { class: "graph-wrap" });
  wrap.appendChild(legend);
  wrap.appendChild(svg);
  p.appendChild(h("p", { class: "muted", style: "font-size:12px;margin:0 0 10px" }, `${nodes.length} assets · ${rels.total} relationships`));
  p.appendChild(wrap);
}

async function loadVulns(p) {
  const [applic, findings] = await Promise.all([
    api(`/scans/${state.scanId}/vulnerability-applicability`),
    api(`/scans/${state.scanId}/confirmed-findings`),
  ]);
  p.innerHTML = "";
  p.appendChild(h("div", { class: "section-title" }, `Confirmed findings (${findings.total})`));
  if (findings.total) {
    const fmap = await assetMap();
    const fb = h("tbody");
    findings.items.forEach((f) => {
      fb.appendChild(
        h("tr", { class: "clickable", onclick: () => showFindingDetail(f, fmap) },
          h("td", {}, f.title),
          h("td", {}, h("span", { class: "pill sev-" + String(f.source_severity || "unknown").toLowerCase() }, f.source_severity || "—")),
          h("td", {}, f.contextual_priority || "—"),
          h("td", { class: "mono" }, (f.evidence_ids || []).length + " evidence"),
          h("td", {}, f.confirmed_by || "—"))
      );
    });
    p.appendChild(h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Title"), h("th", {}, "Severity"), h("th", {}, "Priority"), h("th", {}, "Evidence"), h("th", {}, "Confirmed by"))), fb));
  } else {
    p.appendChild(h("p", { class: "empty-note" }, "No confirmed findings. Confirmation requires recorded evidence via validation."));
  }

  p.appendChild(h("div", { class: "section-title" }, `Vulnerability applicability (${applic.total})`));
  const counts = {};
  applic.items.forEach((i) => (counts[i.state] = (counts[i.state] || 0) + 1));
  const grid = h("div", { class: "stat-grid" });
  Object.entries(counts).forEach(([s, c]) => grid.appendChild(statBox(c, s, s === "APPLICABLE" ? "warn" : "")));
  p.appendChild(grid);

  const rows = applic.items.filter((i) => i.state === "APPLICABLE").slice(0, 200);
  if (rows.length) {
    const body = h("tbody");
    rows.forEach((r) =>
      body.appendChild(
        h("tr", { class: "clickable", onclick: () => showVulnDetail(r) },
          h("td", {}, h("span", { class: "pill state-APPLICABLE" }, r.class_code || "—")),
          h("td", { class: "mono" }, r.asset_id.slice(0, 8)),
          h("td", {}, r.confidence != null ? r.confidence.toFixed(2) : "—"),
          h("td", {}, r.explanation || "—"))
      )
    );
    p.appendChild(h("div", { class: "section-title" }, "Applicable classes (click a row for detail)"));
    p.appendChild(h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Class"), h("th", {}, "Asset"), h("th", {}, "Conf."), h("th", {}, "Rationale"))), body));
  }
}

async function loadHypotheses(p) {
  const data = await api(`/scans/${state.scanId}/hypotheses`);
  p.innerHTML = "";
  if (!data.total) return void (p.innerHTML = '<p class="empty-note">No hypotheses generated yet. Run AI validation to generate and prioritize.</p>');
  const body = h("tbody");
  data.items.forEach((hy) => {
    body.appendChild(
      h("tr", { class: "clickable", onclick: () => showHypothesisDetail(hy.id) },
        h("td", {}, hy.title),
        h("td", {}, h("span", { class: "pill mode" }, hy.hypothesis_type)),
        h("td", {}, h("span", { class: "pill" }, hy.status)),
        h("td", {}, hy.confidence != null ? hy.confidence.toFixed(2) : "—"),
        h("td", { class: "mono" }, (hy.affected_asset_ids || []).length + " assets"))
    );
  });
  p.appendChild(h("p", { class: "muted", style: "font-size:12px;margin:0 0 8px" }, "Click a row for full detail (where + what kind + evidence)."));
  p.appendChild(h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Hypothesis"), h("th", {}, "Type"), h("th", {}, "Status"), h("th", {}, "Conf."), h("th", {}, "Scope"))), body));
}

async function loadValidation(p) {
  const backlog = await api(`/scans/${state.scanId}/validation-backlog`);
  p.innerHTML = "";
  p.appendChild(
    h("div", { class: "note" },
      "Validation tasks are the analyst worklist. AI ranks and assigns them; confirmation still requires recorded evidence.")
  );
  if (!backlog.items.length) {
    p.appendChild(h("p", { class: "empty-note" }, 'No validation tasks yet. Use "Run AI validation" to execute safe automated checks and build the assignment queue.'));
    return;
  }
  const sorted = [...backlog.items].sort((a, b) => (b.priority || 0) - (a.priority || 0));
  sorted.forEach((t) => {
    p.appendChild(
      h("div", { class: "assign-card" },
        h("div", { class: "assign-top" },
          h("div", {}, h("strong", {}, t.validation_goal || "Validation task")),
          h("div", {},
            h("span", { class: "pill mode" }, t.testing_mode || "MANUAL"),
            " ",
            h("span", { class: "pill" }, t.status),
            " ",
            h("span", { class: "prio" }, "P" + (t.priority ?? "—")))
        ),
        h("div", { class: "muted", style: "margin-top:6px;font-size:12px" },
          `Assigned: ${t.assigned_to || "unassigned"} · ${(t.asset_ids || []).length} asset(s)`),
        t.suggested_safe_checks && t.suggested_safe_checks.length
          ? h("ul", { style: "margin:8px 0 0;font-size:12px;color:var(--muted)" },
              ...t.suggested_safe_checks.map((c) => h("li", {}, c)))
          : null)
    );
  });
}

async function loadMcpValidation(p) {
  const [data, connectors, map] = await Promise.all([
    api(`/scans/${state.scanId}/mcp-validation`),
    api("/ui/validation-connectors"),
    assetMap(),
  ]);
  p.innerHTML = "";
  p.appendChild(
    h("div", { class: "note" },
      "Tool validation runs all available connectors (nuclei, Burp MCP, sqlmap MCP). Use username/password in the sidebar for authenticated targets. Positive matches open validation tasks — analyst confirmation still required.")
  );
  if (connectors.items.length) {
    const cl = h("ul", { style: "font-size:12px;color:var(--muted);margin:0 0 10px 18px" });
    connectors.items.forEach((c) =>
      cl.appendChild(h("li", {}, `${c.name} (${c.safety_class}) \u2014 ${c.available ? "ready" : "not available"}${c.active ? ", active-gated" : ""}`))
    );
    p.appendChild(cl);
  }
  const activeBox = h("label", { style: "display:flex;align-items:center;gap:8px;font-size:12px;margin:8px 0" },
    h("input", { type: "checkbox", id: "mcpActiveAllowed" }),
    "Allow active validation (sqlmap MCP; authorized targets only)"
  );
  p.appendChild(activeBox);
  const btn = h("button", { class: "secondary", style: "margin:8px 0" }, "Run tool validation");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Running validators\u2026";
    const activeAllowed = !!document.getElementById("mcpActiveAllowed")?.checked;
    const creds = scanCredentials();
    try {
      const res = await api(`/scans/${state.scanId}/mcp-validate`, {
        method: "POST",
        body: JSON.stringify({
          active_allowed: activeAllowed,
          username: creds.username,
          password: creds.password,
        }),
      });
      const skipped = (res.skipped || []).length ? ` · skipped: ${res.skipped.join("; ")}` : "";
      toast(`All tools: ${res.assets_validated} asset(s) via ${(res.connectors || []).join(", ")} — ${res.corroborated} corroborated, ${res.tasks_created} task(s)${skipped}`);
      delete state.cache.validation;
      loadTab("mcp");
    } catch (e) {
      toast(e.message, true);
      btn.disabled = false;
      btn.textContent = "Run tool validation";
    }
  });
  p.appendChild(btn);

  if (!data.total_runs) {
    p.appendChild(h("p", { class: "empty-note" }, "No tool-validation runs yet. Enable Burp/sqlmap in .env if needed, then click \u201cRun tool validation\u201d."));
    return;
  }
  const body = h("tbody");
  data.runs.forEach((r) => {
    body.appendChild(
      h("tr", {},
        h("td", {}, h("span", { class: "pill" }, r.connector || "—")),
        h("td", {}, h("span", { class: "pill state-" + (r.status === "CORROBORATED" ? "APPLICABLE" : "NOT_APPLICABLE") }, r.status)),
        h("td", { class: "mono" }, r.asset_id ? assetLabel(map, r.asset_id) : "—"),
        h("td", {}, (r.class_codes || []).join(", ") || "—"),
        h("td", {}, String(r.finding_count ?? 0)),
        h("td", { class: "muted", style: "font-size:12px" }, r.detail || (r.tags || []).join(",")))
    );
  });
  p.appendChild(h("div", { class: "section-title" }, "Validation runs"));
  p.appendChild(h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Connector"), h("th", {}, "Result"), h("th", {}, "Where"), h("th", {}, "Classes"), h("th", {}, "Findings"), h("th", {}, "Detail"))), body));

  if ((data.findings || []).length) {
    const fb = h("tbody");
    data.findings.forEach((f) => {
      fb.appendChild(
        h("tr", {},
          h("td", {}, f.template_id || "—"),
          h("td", {}, h("span", { class: "pill sev-" + String(f.severity || "unknown").toLowerCase() }, f.severity || "—")),
          h("td", {}, f.name || "—"),
          h("td", { class: "mono", style: "font-size:12px" }, f.matched_at || "—"))
      );
    });
    p.appendChild(h("div", { class: "section-title" }, "Corroborating findings"));
    p.appendChild(h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Template"), h("th", {}, "Severity"), h("th", {}, "Name"), h("th", {}, "Matched at"))), fb));
  }
}

async function loadAI(p) {
  const data = await api(`/scans/${state.scanId}/ai-enrichments`);
  p.innerHTML = "";
  if (!data.items.length) {
    p.appendChild(h("p", { class: "empty-note" }, 'No AI advisory yet. Click "Run AI validation" to generate one.'));
    return;
  }
  data.items.forEach((item) => {
    const out = item.output || {};
    p.appendChild(h("div", { class: "section-title" }, `${item.enrichment_type || "Advisory"} · ${item.provider || "?"}`));
    if (out.summary) p.appendChild(h("p", { style: "font-size:13px" }, out.summary));
    if ((out.priority_classes || []).length) {
      const body = h("tbody");
      out.priority_classes.forEach((pc, i) =>
        body.appendChild(
          h("tr", {},
            h("td", {}, h("span", { class: "prio" }, "#" + (i + 1))),
            h("td", {}, h("span", { class: "pill state-APPLICABLE" }, pc.class_code)),
            h("td", {}, pc.rationale || "—"),
            h("td", {}, pc.recommended_validation || "—"))
        )
      );
      p.appendChild(h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Rank"), h("th", {}, "Class"), h("th", {}, "Rationale"), h("th", {}, "Recommended validation"))), body));
    }
    if ((out.limitations || []).length) {
      p.appendChild(h("div", { class: "section-title" }, "Limitations"));
      p.appendChild(h("ul", { style: "font-size:12px;color:var(--muted)" }, ...out.limitations.map((l) => h("li", {}, l))));
    }
  });
}

async function runFullValidation() {
  if (!state.scanId) return;
  const btn = document.getElementById("fullValidateBtn");
  btn.disabled = true;
  btn.textContent = "Running all validators…";
  const creds = scanCredentials();
  const activeAllowed = !!document.getElementById("mcpActiveInput")?.checked;
  try {
    const res = await api(`/scans/${state.scanId}/full-validate`, {
      method: "POST",
      body: JSON.stringify({
        active_allowed: activeAllowed,
        username: creds.username,
        password: creds.password,
      }),
    });
    const ai = res.ai || {};
    const mcp = res.mcp || {};
    toast(
      `Full validation complete · AI: ${(ai.assignments || []).length} tasks · Tools: ${(mcp.connectors || []).join(", ")} · ${mcp.corroborated || 0} corroborated`
    );
    state.cache = {};
    selectTab("validation");
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run full validation";
  }
}

async function refreshReportFreshness() {
  if (!state.scanId) return;
  try {
    const freshness = await api(`/scans/${state.scanId}/report-freshness?force=true`);
    const status = freshness.status || "UNKNOWN";
    toast(`Report freshness: ${status}${freshness.fallback_used ? " (full-hash fallback)" : ""}`);
    state.cache = {};
    refreshCurrent();
  } catch (e) {
    toast(e.message, true);
  }
}

async function downloadReport(force = false) {
  if (!state.scanId) return;
  const btn = document.getElementById("reportBtn");
  btn.disabled = true;
  btn.textContent = "Generating…";
  try {
    const report = await api(
      `/scans/${state.scanId}/report${force ? "?force_regenerate=true" : ""}`
    );
    const snap = report.report_snapshot;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const name = (document.getElementById("scanTitle")?.textContent || state.scanId).replace(/[^\w.-]+/g, "_");
    a.href = url;
    a.download = `vapt-report-${name}.json`;
    a.click();
    URL.revokeObjectURL(url);
    const delivery = report.report_delivery || {};
    toast(
      delivery.source === "snapshot"
        ? `Snapshot report · ${(delivery.content_hash || snap?.content_hash || "").slice(0, 12)}`
        : snap
          ? `Report regenerated · v${snap.report_version} · ${snap.content_hash.slice(0, 12)}`
          : "Assessment report downloaded"
    );
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Generate report";
  }
}

async function runAiValidation() {
  if (!state.scanId) return;
  const btn = document.getElementById("aiValidateBtn");
  btn.disabled = true;
  btn.textContent = "Running…";
  try {
    const res = await api(`/scans/${state.scanId}/ai-validate`, { method: "POST" });
    toast(`AI validation done · ${res.assignments.length} tasks assigned · ${res.finding_candidates} candidates`);
    state.cache = {};
    selectTab("validation");
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run AI validation";
  }
}

/* ---------- tool selection ---------- */
async function openToolsModal() {
  const wrap = h("div", {}, h("p", { class: "muted", style: "font-size:12px;margin-top:0" }, "Enable or disable tools for automated scans. Greyed rows are not installed. Changes apply to new scans."));
  openModal("Configure tools", wrap);
  try {
    const data = await api("/ui/tools");
    data.groups.forEach((g) => {
      const group = h("div", { class: "tool-group" }, h("h3", {}, `${g.capability_group} (${g.tools.length})`));
      g.tools.forEach((t) => {
        const input = h("input", { type: "checkbox" });
        input.checked = t.enabled;
        input.addEventListener("change", async () => {
          try {
            await api("/ui/tools/toggle", { method: "POST", body: JSON.stringify({ tool: t.tool, enabled: input.checked }) });
          } catch (e) {
            input.checked = !input.checked;
            toast(e.message, true);
          }
        });
        group.appendChild(
          h("div", { class: "tool-row" + (t.available ? "" : " unavailable") },
            h("div", {},
              h("strong", {}, t.tool),
              h("div", { class: "tool-meta" }, `${t.safety_class} · ${(t.capabilities || []).join(", ")}${t.available ? "" : " · not installed"}`)),
            h("label", { class: "switch" }, input, h("span", { class: "slider" })))
        );
      });
      wrap.appendChild(group);
    });
  } catch (e) {
    wrap.appendChild(h("p", { class: "empty-note" }, e.message));
  }
}

async function cancelScan() {
  if (!state.scanId) return;
  try {
    await api(`/scans/${state.scanId}/cancel`, { method: "POST" });
    toast("Scan cancelled");
    refreshCurrent();
  } catch (e) {
    toast(e.message, true);
  }
}

/* ---------- drill-down detail ---------- */
async function showHypothesisDetail(id) {
  try {
    const [hy, map] = await Promise.all([api(`/hypotheses/${id}`), assetMap()]);
    const wrap = h("div", {});
    wrap.appendChild(detailRow("Title", hy.title));
    wrap.appendChild(detailRow("Kind", h("span", { class: "pill mode" }, hy.hypothesis_type)));
    wrap.appendChild(detailRow("Status", h("span", { class: "pill" }, hy.status)));
    wrap.appendChild(detailRow("Confidence", hy.confidence != null ? hy.confidence.toFixed(2) : "—"));
    wrap.appendChild(detailRow("Description", hy.description || "—"));
    const where = (hy.affected_asset_ids || []).map((aid) => h("div", {}, assetLabel(map, aid)));
    wrap.appendChild(detailRow("Where (assets)", where.length ? h("div", {}, ...where) : "—"));
    wrap.appendChild(detailRow("Supporting evidence", (hy.supporting_evidence_ids || []).length + " item(s)"));
    if (hy.validation_requirements && Object.keys(hy.validation_requirements).length) {
      wrap.appendChild(detailRow("Validation needs", h("pre", { class: "mono", style: "white-space:pre-wrap;margin:0" }, JSON.stringify(hy.validation_requirements, null, 2))));
    }
    wrap.appendChild(detailRow("Test plan", hy.test_plan_id || "—"));
    wrap.appendChild(detailRow("Verdict", hy.verdict_id || "not yet confirmed"));
    openModal("Hypothesis detail", wrap);
  } catch (e) {
    toast(e.message, true);
  }
}

async function showVulnDetail(row) {
  const map = await assetMap();
  const wrap = h("div", {});
  wrap.appendChild(detailRow("What kind", h("span", { class: "pill state-APPLICABLE" }, row.class_code || "—")));
  wrap.appendChild(detailRow("State", h("span", { class: "pill state-" + row.state }, row.state)));
  wrap.appendChild(detailRow("Where (asset)", assetLabel(map, row.asset_id)));
  wrap.appendChild(detailRow("Confidence", row.confidence != null ? row.confidence.toFixed(2) : "—"));
  wrap.appendChild(detailRow("Rules applied", (row.rule_ids || []).join(", ") || "—"));
  wrap.appendChild(detailRow("Rationale", row.explanation || "—"));
  openModal("Vulnerability detail", wrap);
}

function showFindingDetail(f, map) {
  const wrap = h("div", {});
  wrap.appendChild(detailRow("Title", f.title));
  wrap.appendChild(detailRow("Severity", h("span", { class: "pill sev-" + String(f.source_severity || "unknown").toLowerCase() }, f.source_severity || "—")));
  wrap.appendChild(detailRow("Priority", f.contextual_priority || "—"));
  wrap.appendChild(detailRow("Description", f.description || "—"));
  const where = (f.affected_asset_ids || []).map((aid) => h("div", {}, assetLabel(map, aid)));
  wrap.appendChild(detailRow("Where (assets)", where.length ? h("div", {}, ...where) : "—"));
  wrap.appendChild(detailRow("CWE", (f.cwe_ids || []).join(", ") || "—"));
  wrap.appendChild(detailRow("CVE", (f.cve_ids || []).join(", ") || "—"));
  wrap.appendChild(detailRow("Evidence", (f.evidence_ids || []).length + " item(s)"));
  wrap.appendChild(detailRow("Confirmed by", f.confirmed_by || "—"));
  openModal("Confirmed finding", wrap);
}

/* ---------- init ---------- */
function init() {
  document.getElementById("scanForm").addEventListener("submit", startScan);
  document.getElementById("refreshBtn").addEventListener("click", refreshCurrent);
  document.getElementById("fullValidateBtn").addEventListener("click", runFullValidation);
  document.getElementById("reportBtn").addEventListener("click", (e) => downloadReport(e.shiftKey));
  const refreshFreshnessBtn = document.getElementById("refreshFreshnessBtn");
  if (refreshFreshnessBtn) {
    refreshFreshnessBtn.addEventListener("click", refreshReportFreshness);
  }
  document.getElementById("aiValidateBtn").addEventListener("click", runAiValidation);
  document.getElementById("toolsBtn").addEventListener("click", openToolsModal);
  document.getElementById("cancelBtn").addEventListener("click", cancelScan);
  document.getElementById("modalClose").addEventListener("click", closeModal);
  document.getElementById("errorClose").addEventListener("click", closeError);
  document.getElementById("modalOverlay").addEventListener("click", (e) => {
    if (e.target.id === "modalOverlay") closeModal();
  });
  document.getElementById("errorOverlay").addEventListener("click", (e) => {
    if (e.target.id === "errorOverlay") closeError();
  });
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => selectTab(t.dataset.tab))
  );
  checkApi();
  loadScanHistory();
  // resume polling any in-flight jobs
  api("/ui/jobs").then((d) => d.items.forEach((j) => {
    if (j.status === "RUNNING" || j.status === "QUEUED") pollJob(j.job_id);
  })).catch(() => {});
}

document.addEventListener("DOMContentLoaded", init);
