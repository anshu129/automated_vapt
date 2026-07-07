const API = "/api/v1";

const state = {
  scanId: null,
  jobPollers: {},
  activeTab: "overview",
  cache: {},
};

/* ---------- helpers ---------- */
async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch (_) {}
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
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
  const t = h("div", { class: "toast" + (isErr ? " err" : "") }, msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

function panel(name) {
  return document.querySelector(`.panel[data-panel="${name}"]`);
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
            `${s.status} · ${s.created_at ? new Date(s.created_at).toLocaleString() : ""}`
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
          toast(`Scan failed: ${job.error || "unknown"}`, true);
        }
      }
    } catch (e) {
      clearInterval(poller.timer);
    }
  };
  poller.timer = setInterval(tick, 2500);
  tick();
}

function updateProgress(job) {
  const bar = document.getElementById("progressBar");
  const fill = document.getElementById("progressFill");
  const label = document.getElementById("progressLabel");
  const badge = document.getElementById("scanStatusBadge");
  const phases = ["queued", "reconnaissance", "planning", "ai_validation", "completed"];
  if (job.status === "COMPLETED" || job.status === "FAILED") {
    bar.classList.add("hidden");
  } else {
    bar.classList.remove("hidden");
    const idx = Math.max(0, phases.indexOf(job.phase));
    fill.style.width = `${(idx / (phases.length - 1)) * 100}%`;
    label.textContent = `${job.phase} · ${job.elapsed_seconds || 0}s / budget ${job.time_budget_minutes}m`;
  }
  badge.textContent = job.status;
  badge.className = "badge " + job.status;
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
    const job = await api("/ui/scans", {
      method: "POST",
      body: JSON.stringify({
        host,
        name: document.getElementById("nameInput").value.trim() || null,
        run_ai: document.getElementById("aiInput").checked,
        time_budget_minutes: parseInt(document.getElementById("budgetInput").value || "30", 10),
      }),
    });
    toast(`Assessment queued for ${job.target}`);
    pollJob(job.job_id);
    openScan(job.scan_id);
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Start assessment";
  }
}

/* ---------- scan view ---------- */
async function openScan(scanId) {
  state.scanId = scanId;
  state.cache = {};
  document.getElementById("emptyState").classList.add("hidden");
  document.getElementById("scanView").classList.remove("hidden");
  selectTab(state.activeTab || "overview");
  try {
    const scan = await api(`/scans/${scanId}`);
    document.getElementById("scanTitle").textContent = scan.name || scanId;
    document.getElementById("scanMeta").textContent = `Scan ${scanId} · status ${scan.status}`;
    const badge = document.getElementById("scanStatusBadge");
    badge.textContent = scan.status;
    badge.className = "badge " + scan.status;
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
      ai: loadAI,
    };
    await loaders[name](p);
  } catch (e) {
    p.innerHTML = `<p class="empty-note">${esc(e.message)}</p>`;
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
  const [assets, rels, applic, hyps, backlog, findings] = await Promise.all([
    api(`/scans/${id}/assets`),
    api(`/scans/${id}/relationships`),
    api(`/scans/${id}/vulnerability-applicability`),
    api(`/scans/${id}/hypotheses`),
    api(`/scans/${id}/validation-backlog`),
    api(`/scans/${id}/confirmed-findings`),
  ]);
  const applicable = applic.items.filter((i) => i.state === "APPLICABLE").length;
  p.innerHTML = "";
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
    const fb = h("tbody");
    findings.items.forEach((f) => {
      fb.appendChild(
        h("tr", {},
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
        h("tr", {},
          h("td", {}, h("span", { class: "pill state-APPLICABLE" }, r.class_code || "—")),
          h("td", { class: "mono" }, r.asset_id.slice(0, 8)),
          h("td", {}, r.confidence != null ? r.confidence.toFixed(2) : "—"),
          h("td", {}, r.explanation || "—"))
      )
    );
    p.appendChild(h("div", { class: "section-title" }, "Applicable classes"));
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
      h("tr", {},
        h("td", {}, hy.title),
        h("td", {}, h("span", { class: "pill mode" }, hy.hypothesis_type)),
        h("td", {}, h("span", { class: "pill" }, hy.status)),
        h("td", {}, hy.confidence != null ? hy.confidence.toFixed(2) : "—"),
        h("td", { class: "mono" }, (hy.affected_asset_ids || []).length + " assets"))
    );
  });
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

/* ---------- init ---------- */
function init() {
  document.getElementById("scanForm").addEventListener("submit", startScan);
  document.getElementById("refreshBtn").addEventListener("click", refreshCurrent);
  document.getElementById("aiValidateBtn").addEventListener("click", runAiValidation);
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
