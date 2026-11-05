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
