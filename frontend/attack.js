"use strict";

const SVGNS = "http://www.w3.org/2000/svg";
const $ = (s) => document.querySelector(s);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Known lab targets -> the real site you can open during a demo.
const TARGET_URL = {
  webapp: "http://localhost:8080",
  keycloak: "http://localhost:8180",
  caldera: "http://localhost:8888",
};

// Board geometry (SVG user units).
const W = 1200, H = 680;
const ATTACKER = { x: 170, y: H / 2 };
const DEFENDER = { x: 1030, y: H / 2 };
const TARGET_X = 600;
const CARD = { w: 236, h: 78, dw: 200, dh: 92 };

let SPEED = 1;
const dur = (ms) => ms * SPEED;

const board = $("#board");
let edgeLayer, cardLayer, fxLayer;
const nodes = new Map(); // target name -> {cx, cy, card, edgeAttack, edgeDefend}

function el(tag, attrs = {}) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
}

function card(cx, cy, w, h, cls, html) {
  const fo = el("foreignObject", { x: cx - w / 2, y: cy - h / 2, width: w, height: h });
  const div = document.createElement("div");
  div.className = "node " + cls;
  div.innerHTML = html;
  fo.appendChild(div);
  return { fo, div };
}

function zoneHeader(x, text, color) {
  const t = el("text", { x, y: 34, "text-anchor": "middle", class: "zone-label", fill: color });
  t.textContent = text;
  return t;
}

function resetBoard() {
  board.replaceChildren();
  nodes.clear();

  const defs = el("defs");
  defs.innerHTML =
    '<marker id="ahead" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto">' +
    '<path d="M0,0 L9,4.5 L0,9 Z" fill="#ff4d5e"></path></marker>';
  edgeLayer = el("g");
  cardLayer = el("g");
  fxLayer = el("g");
  board.append(defs, edgeLayer, cardLayer, fxLayer);

  board.append(
    zoneHeader(ATTACKER.x, "ATTACKER", "#ff6b78"),
    zoneHeader(TARGET_X, "TARGET SITES", "#9aa6c2"),
    zoneHeader(DEFENDER.x, "DEFENDER (blue + ledger)", "#4da3ff"),
  );

  const atk = card(ATTACKER.x, ATTACKER.y, CARD.dw, CARD.dh, "attacker",
    `<div class="title">🛰️ AEGIS red agent</div><div class="sub">bounded, non-destructive validation</div>`);
  const def = card(DEFENDER.x, DEFENDER.y, CARD.dw, CARD.dh, "defender",
    `<div class="title">🛡️ AEGIS blue + ledger</div><div class="sub">detect · prove fix · record</div>`);
  cardLayer.append(atk.fo, def.fo);
}

function setPhase(name) {
  document.querySelectorAll(".phase").forEach((p) => p.classList.toggle("active", p.dataset.phase === name));
}

function layoutTargets(names) {
  const n = names.length || 1;
  const top = 90, bottom = H - 90;
  const step = n > 1 ? (bottom - top) / (n - 1) : 0;
  names.forEach((name, i) => {
    const cy = n > 1 ? top + step * i : H / 2;
    const cx = TARGET_X;
    const eA = el("line", { x1: ATTACKER.x + CARD.dw / 2, y1: ATTACKER.y, x2: cx - CARD.w / 2, y2: cy, class: "edge", "marker-end": "url(#ahead)" });
    const eD = el("line", { x1: DEFENDER.x - CARD.dw / 2, y1: DEFENDER.y, x2: cx + CARD.w / 2, y2: cy, class: "edge detect", "stroke-opacity": "0" });
    edgeLayer.append(eA, eD);
    const url = TARGET_URL[name];
    const c = card(cx, cy, CARD.w, CARD.h, "", `<div class="title">${url ? "🌐" : "🧩"} ${escapeHtml(name)}</div><div class="sub" data-sub>awaiting…</div>`);
    if (url) { c.div.dataset.url = url; c.div.title = "Open " + url; }
    cardLayer.appendChild(c.fo);
    nodes.set(name, { cx, cy, card: c.div, edgeAttack: eA, edgeDefend: eD });
  });
}

async function shot(from, to, cls) {
  const c = el("circle", { r: 7, cx: from.x, cy: from.y, class: "shot " + cls });
  fxLayer.appendChild(c);
  const anim = c.animate(
    [{ cx: from.x, cy: from.y, opacity: 1 }, { cx: to.x, cy: to.y, opacity: 1 }],
    { duration: dur(650), easing: "cubic-bezier(.5,0,.6,1)" }
  );
  // Web Animations can't tween SVG geometry attrs everywhere; drive manually as fallback.
  const start = performance.now(), D = dur(650);
  await new Promise((res) => {
    function frame(t) {
      const k = Math.min(1, (t - start) / D);
      c.setAttribute("cx", from.x + (to.x - from.x) * k);
      c.setAttribute("cy", from.y + (to.y - from.y) * k);
      if (k < 1) requestAnimationFrame(frame); else res();
    }
    requestAnimationFrame(frame);
  });
  try { anim.cancel(); } catch (e) { /* ignore */ }
  c.remove();
}

function setSub(node, html) { node.card.querySelector("[data-sub]").innerHTML = html; }

function logFeed(kind, title, sub) {
  const li = document.createElement("li");
  li.className = "k-" + kind;
  li.innerHTML = `<strong>${escapeHtml(title)}</strong>${sub ? `<br><small>${sub}</small>` : ""}`;
  $("#feed").prepend(li);
}

const counts = { paths: 0, breached: 0, detected: 0, blocked: 0, closed: 0 };
function bump(k) { counts[k]++; $("#c" + k[0].toUpperCase() + k.slice(1)).textContent = counts[k]; }

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function playAction(row) {
  const name = row.action.target;
  const node = nodes.get(name);
  if (!node) return;
  const pos = { x: node.cx, y: node.cy };

  bump("paths");
  setPhase("attack");
  node.card.classList.add("firing");
  node.edgeAttack.classList.add("hot");
  await shot(ATTACKER, pos, "");
  node.card.classList.remove("firing");

  const tech = row.action.technique;

  // Blocked by the safety agent before any probe ran.
  if (!row.result) {
    node.card.classList.add("blocked");
    node.edgeAttack.classList.remove("hot");
    const why = (row.safety && row.safety.reasons || []).join("; ");
    setSub(node, `<span class="pill">blocked by safety</span>`);
    logFeed("block", `Safety blocked ${tech} on ${name}`, escapeHtml(why));
    bump("blocked");
    await sleep(dur(350));
    return;
  }

  const ev = row.result.evidence || {};
  const mode = ev.mode || "simulated";
  const modeTag = `<span class="pill ${mode === "live" ? "mode-live" : ""}">${mode === "live" ? "LIVE" : "SIM"}</span>`;

  if (!row.result.succeeded) {
    node.card.classList.add("repelled");
    node.edgeAttack.classList.remove("hot");
    const outcome = row.result.outcome || "repelled";
    setSub(node, `${modeTag} <span class="pill">repelled · ${escapeHtml(outcome)}</span>`);
    logFeed("info", `Repelled on ${name}`, `${escapeHtml(tech)} — ${escapeHtml(outcome)}`);
    await sleep(dur(350));
    return;
  }

  // Breached.
  node.card.classList.add("breached");
  const ep = ev.endpoint ? ` · ${escapeHtml(ev.endpoint)}` : "";
  setSub(node, `${modeTag} <span class="pill">BREACHED</span> ${escapeHtml(tech)}${ep}`);
  logFeed("breach", `Breached ${name}`, `${escapeHtml(tech)} (${mode})${ep}`);
  bump("breached");
  await sleep(dur(250));

  // Detection: ping back to the defender/SOC.
  const det = row.detection || {};
  if (det.detected || det.quality === "detected" || det.quality === "detected-late") {
    setPhase("detect");
    node.edgeDefend.setAttribute("stroke-opacity", "1");
    await shot(pos, DEFENDER, "detect");
    bump("detected");
    logFeed("detect", `Detected on ${name}`, `${escapeHtml(det.quality || "detected")}${det.latency_s ? " · " + det.latency_s + "s" : ""}`);
  } else {
    logFeed("detect", `Missed on ${name}`, "no rule matched — blue proposes one");
  }

  // Remediation: proven fixes travel defender -> target and close it.
  for (const entry of row.fixes || []) {
    if (!entry.proof || entry.proof.verdict !== "proven") continue;
    setPhase("respond");
    await shot(DEFENDER, pos, "fix");
    node.card.classList.remove("breached");
    node.card.classList.add("closed");
    node.edgeAttack.classList.remove("hot");
    node.edgeAttack.classList.add("cool");
    setSub(node, `<span class="pill">CLOSED</span> ${escapeHtml(entry.fix.fix_type || entry.fix.title)}`);
    logFeed("close", `Closed on ${name}`, escapeHtml(entry.fix.title));
    bump("closed");
    await sleep(dur(300));
    break; // one visible closure per target keeps the board readable
  }
}

function showExposure(report) {
  const before = report.exposure_before, after = report.exposure_after_if_applied;
  $("#cExposure").textContent = `${before.toFixed(1)} → ${after.toFixed(1)}`;
  const pct = before > 0 ? Math.max(4, Math.round((after / before) * 100)) : 100;
  $("#expoFill").style.width = pct + "%";
}

async function launch() {
  const btn = $("#launch");
  btn.disabled = true;
  const prev = btn.textContent;
  btn.textContent = "Attacking…";
  for (const k of Object.keys(counts)) { counts[k] = 0; }
  ["Paths", "Breached", "Detected", "Blocked", "Closed"].forEach((k) => ($("#c" + k).textContent = "0"));
  $("#feed").replaceChildren();
  $("#cExposure").textContent = "—";
  $("#expoFill").style.width = "100%";
  resetBoard();

  const live = $("#liveToggle").checked;
  try {
    const res = await fetch(`/api/engage?top_paths=6&max_actions=8&live=${live}`, { method: "POST" });
    if (!res.ok) throw new Error("engage failed " + res.status);
    const report = await res.json();

    const order = [];
    for (const row of report.actions) {
      if (!order.includes(row.action.target)) order.push(row.action.target);
    }
    layoutTargets(order);
    logFeed("info", `Engagement started`, `${report.actions.length} actions · ${live ? "LIVE probes" : "simulated"}`);
    await sleep(dur(400));

    for (const row of report.actions) {
      await playAction(row);
      await sleep(dur(200));
    }

    setPhase("verify");
    showExposure(report);
    const modes = report.execution_modes || {};
    logFeed("info", "Engagement complete",
      `${report.validated} validated · ${report.fixes_proven} fixes proven · ledger ${report.ledger_ok ? "verified ✓" : "BROKEN ✗"}` +
      (modes.live ? ` · ${modes.live} live` : ""));
  } catch (err) {
    logFeed("block", "Engagement error", escapeHtml(err.message));
  } finally {
    btn.disabled = false;
    btn.textContent = prev;
  }
}

$("#speed").addEventListener("change", (e) => { SPEED = parseFloat(e.target.value) || 1; });
$("#launch").addEventListener("click", launch);
board.addEventListener("click", (e) => {
  const div = e.target.closest(".node.breached, .node.closed");
  if (div && div.dataset.url) window.open(div.dataset.url, "_blank", "noopener");
});

resetBoard();
layoutTargets(["webapp", "database", "keycloak"]);
logFeed("info", "Ready", "Press ▶ Launch attack to run a safety-gated red–blue pass.");
