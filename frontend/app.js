const state = {
  findings: [],
  paths: [],
  summary: {},
  source: "",
  severity: "",
  at: "",
};

const severityRank = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

async function getJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function withAt(url) {
  return state.at ? `${url}?at=${encodeURIComponent(state.at)}` : url;
}

async function loadAll() {
  const status = document.querySelector("#status");
  try {
    const [findings, paths, timeline] = await Promise.all([
      getJson(withAt("/api/findings")),
      getJson(withAt("/api/paths")),
      getJson("/api/timeline"),
    ]);
    state.findings = findings.findings || [];
    state.paths = paths.paths || [];
    state.summary = paths.summary || {};
    status.textContent = state.at ? "Historical" : "Live";
    status.style.color = state.at ? "#b76e00" : "#276749";
    populateTimeline(timeline.changes || []);
    populateSources();
    render();
    renderPaths();
  } catch (error) {
    status.textContent = "API error";
    status.style.color = "#b42318";
    document.querySelector("#emptyState").hidden = false;
  }
}

function populateTimeline(changes) {
  const select = document.querySelector("#asOf");
  select.replaceChildren(new Option("Now", ""));
  for (const ts of [...changes].reverse()) {
    select.appendChild(new Option(new Date(ts).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" }), ts));
  }
  select.value = state.at;
}

function populateSources() {
  const select = document.querySelector("#sourceFilter");
  select.replaceChildren(new Option("All sources", ""));
  const sources = [...new Set(state.findings.map((finding) => finding.source_tool))].sort();
  for (const source of sources) {
    select.appendChild(new Option(source.toUpperCase(), source));
  }
  select.value = sources.includes(state.source) ? state.source : "";
}

function renderPaths() {
  const s = state.summary;
  document.querySelector("#pathCount").textContent = s.paths ?? 0;
  document.querySelector("#validatedCount").textContent = s.validated ?? 0;
  document.querySelector("#exposure").textContent = (s.exposure ?? 0).toFixed(2);
  const list = document.querySelector("#pathsList");
  list.replaceChildren();
  for (const path of state.paths) {
    const item = document.createElement("li");
    item.className = "path";
    const hops = [hop(path.entry, labelForEntry(path))]
      .concat(path.steps.map((step) => hop(step.to, step.label, step.detail)))
      .join('<span class="arrow">&rarr;</span>');
    item.innerHTML = `
      <div class="path-meta">
        <span class="badge ${escapeHtml(path.status)}">${escapeHtml(path.status)}</span>
        <span>value <strong>${path.security_value.toFixed(3)}</strong></span>
        <span>impact ${path.impact}</span>
        <span>confidence ${path.confidence}</span>
        <span>op. risk ${path.operational_risk}</span>
        <span>${path.steps.length} steps</span>
      </div>
      <div class="chain">${hops}</div>`;
    list.appendChild(item);
  }
  document.querySelector("#pathsEmpty").hidden = state.paths.length > 0;
}

function labelForEntry(path) {
  return path.entry === "pos:asset:internet" ? "attacker on the internet" : `foothold on ${path.entry.split(":").pop()}`;
}

function hop(stateId, label, title = "") {
  const kind = stateId.split(":")[0];
  return `<span class="hop ${escapeHtml(kind)}" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`;
}

function render() {
  const filtered = state.findings
    .filter((finding) => !state.source || finding.source_tool === state.source)
    .filter((finding) => !state.severity || finding.severity === state.severity)
    .sort((a, b) => (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9));

  document.querySelector("#totalFindings").textContent = state.findings.length;
  document.querySelector("#highFindings").textContent = state.findings.filter((finding) =>
    ["critical", "high"].includes(finding.severity),
  ).length;

  const body = document.querySelector("#findingsBody");
  body.replaceChildren();
  for (const finding of filtered) {
    const recommendation = finding.blue_ai || {};
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>
        <div class="finding-name">
          <strong>${escapeHtml(finding.name)}</strong>
          <small>${escapeHtml(finding.description || "No description captured yet.")}</small>
        </div>
      </td>
      <td><span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
      <td>${escapeHtml(finding.asset)}</td>
      <td><span class="source">${escapeHtml(finding.source_tool)}</span></td>
      <td>${escapeHtml(finding.classification)}</td>
      <td><span class="reach ${escapeHtml(finding.reachability || "")}">${escapeHtml((finding.reachability || "").replaceAll("_", " "))}${finding.attack_paths ? ` (${finding.attack_paths})` : ""}</span></td>
      <td>${renderRecommendation(recommendation)}</td>
      <td>${finding.confidence == null ? "" : `conf ${finding.confidence}`}${finding.validated ? "<br><strong>validated</strong>" : ""}</td>
    `;
    body.appendChild(row);
  }
  document.querySelector("#emptyState").hidden = filtered.length > 0;
}

function renderRecommendation(recommendation) {
  const steps = Array.isArray(recommendation.fix_steps) ? recommendation.fix_steps : [];
  const renderedSteps = steps
    .map((step) => `<li>${escapeHtml(step)}</li>`)
    .join("");
  return `
    <div class="blue-ai">
      <div class="blue-ai-head">
        <span>Blue AI</span>
        <strong>${escapeHtml(recommendation.priority || "review")}</strong>
      </div>
      <p>${escapeHtml(recommendation.summary || "Review this finding and document a fix.")}</p>
      <ol>${renderedSteps}</ol>
      <small>${escapeHtml(recommendation.verification || "Re-run the source tool after applying the fix.")}</small>
    </div>
  `;
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

document.querySelector("#sourceFilter").addEventListener("change", (event) => {
  state.source = event.target.value;
  render();
});

document.querySelector("#severityFilter").addEventListener("change", (event) => {
  state.severity = event.target.value;
  render();
});

document.querySelector("#asOf").addEventListener("change", (event) => {
  state.at = event.target.value;
  loadAll();
});

document.querySelector("#collectBtn").addEventListener("click", async (event) => {
  event.target.disabled = true;
  try {
    await getJson("/api/collect", { method: "POST" });
    state.at = "";
    await loadAll();
  } finally {
    event.target.disabled = false;
  }
});

loadAll();

async function runEngagement() {
  const btn = document.querySelector("#engageBtn");
  const panel = document.querySelector("#engagePanel");
  btn.disabled = true;
  const prev = btn.textContent;
  btn.textContent = "Running…";
  try {
    const report = await getJson("/api/engage" + (state.at ? `?at=${encodeURIComponent(state.at)}` : ""), { method: "POST" });
    panel.hidden = false;
    document.querySelector("#engValidated").textContent = report.validated;
    document.querySelector("#engBlocked").textContent = report.blocked_by_safety;
    document.querySelector("#engDetected").textContent = report.detections.detected || 0;
    document.querySelector("#engProven").textContent = report.fixes_proven;
    document.querySelector("#engExposure").textContent =
      `${report.exposure_before.toFixed(1)}→${report.exposure_after_if_applied.toFixed(1)}`;
    const ledger = await getJson("/api/ledger/verify");
    const led = document.querySelector("#ledgerState");
    led.textContent = `Evidence ledger: ${ledger.count} records, integrity ${ledger.integrity_ok ? "verified ✓" : "BROKEN ✗"}`;
    led.style.color = ledger.integrity_ok ? "#276749" : "#b42318";
    renderEngagement(report.actions);
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    document.querySelector("#status").textContent = "Engage error";
  } finally {
    btn.disabled = false;
    btn.textContent = prev;
  }
}

function renderEngagement(actions) {
  const list = document.querySelector("#engageList");
  list.replaceChildren();
  for (const row of actions) {
    const item = document.createElement("li");
    item.className = "path";
    const a = row.action;
    const detect = row.detection || {};
    const safety = row.safety || {};
    const head = row.status === "blocked"
      ? `<span class="badge theoretical">blocked by safety</span><span>${escapeHtml((safety.reasons || []).join("; "))}</span>`
      : `<span class="badge ${row.result && row.result.succeeded ? "validated" : "theoretical"}">${escapeHtml(row.status)}</span>
         <span class="detect-tag ${escapeHtml(detect.quality || "")}">detection: ${escapeHtml(detect.quality || "n/a")}${detect.latency_s ? ` (${detect.latency_s}s)` : ""}</span>
         <span>env ${escapeHtml((row.route || {}).environment || "-")}</span>
         <span>blast ${safety.blast_radius ?? "-"}</span>`;
    const fixes = (row.fixes || []).map((entry) => {
      const fix = entry.fix;
      const proof = entry.proof;
      return `
        <div class="fix">
          <div class="fix-head">
            <span class="verdict ${escapeHtml(proof.verdict)}">${escapeHtml(proof.verdict)}</span>
            <strong>${escapeHtml(fix.title)}</strong>
            <span>tier ${escapeHtml(fix.approval_tier)}</span>
          </div>
          <small>Impact: ${escapeHtml(fix.predicted_impact)}</small>
          <small>Rollback: ${escapeHtml(fix.rollback)}</small>
          <small>Proof: attack re-run ${proof.closed ? "blocked" : "still open"}, regression ${proof.regression_ok ? "ok" : "FAILED: " + escapeHtml(proof.broken_workflows.join(", "))}, exposure ${proof.exposure_before}→${proof.exposure_after}</small>
        </div>`;
    }).join("");
    item.innerHTML = `<div class="path-meta">${head}</div>
      <div class="chain"><strong>${escapeHtml(a.name)}</strong></div>${fixes}`;
    list.appendChild(item);
  }
}

document.querySelector("#engageBtn").addEventListener("click", runEngagement);
