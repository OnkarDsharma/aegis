const state = {
  findings: [],
  source: "",
  severity: "",
};

const severityRank = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

async function loadFindings() {
  const status = document.querySelector("#status");
  try {
    const response = await fetch("/api/findings");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    state.findings = payload.findings || [];
    status.textContent = "Live";
    status.style.color = "#276749";
    populateSources();
    render();
  } catch (error) {
    status.textContent = "API error";
    status.style.color = "#b42318";
    document.querySelector("#emptyState").hidden = false;
  }
}

function populateSources() {
  const select = document.querySelector("#sourceFilter");
  const sources = [...new Set(state.findings.map((finding) => finding.source_tool))].sort();
  for (const source of sources) {
    const option = document.createElement("option");
    option.value = source;
    option.textContent = source.toUpperCase();
    select.appendChild(option);
  }
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
  document.querySelector("#toolCount").textContent = new Set(state.findings.map((finding) => finding.source_tool)).size;

  const body = document.querySelector("#findingsBody");
  body.replaceChildren();
  for (const finding of filtered) {
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
      <td>${formatTime(finding.timestamp)}</td>
    `;
    body.appendChild(row);
  }
  document.querySelector("#emptyState").hidden = filtered.length > 0;
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

loadFindings();
