const COLORS = {
  normal: "#2fbf82",
  suspicious: "#f5a623",
  highrisk: "#ef4657",
  accent: "#3ba3ff",
  muted: "#8fa0bd",
};

function badgeClass(classification) {
  if (classification === "HIGH RISK") return "badge-highrisk";
  if (classification === "SUSPICIOUS") return "badge-suspicious";
  return "badge-normal";
}

function fmtDate(d) {
  if (!d) return "-";
  return d.toString().slice(0, 19).replace("T", " ");
}

let timelineChart, donutChart;
let risk3dState = null;

function animateCount(el, target, formatter) {
  const startTime = performance.now();
  const duration = 700;
  function tick(now) {
    const p = Math.min(1, (now - startTime) / duration);
    const eased = 1 - Math.pow(1 - p, 3);
    const value = Math.round(target * eased);
    el.textContent = formatter ? formatter(value) : value;
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function classColorHex(classification) {
  if (classification === "HIGH RISK") return 0xff4d6a;
  if (classification === "SUSPICIOUS") return 0xf5a623;
  return 0x2fd394;
}

// Deterministic 0..1 pseudo-random from a string, so re-renders (regenerate,
// window resize) don't reshuffle points, but rows that would otherwise land
// on the exact same pixel (many NORMAL rows round to similar scores) spread
// into a visible little cloud instead of collapsing into a single dot.
function hash01(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 100000) / 100000;
}

let glowTexture = null;
function getGlowTexture() {
  if (glowTexture) return glowTexture;
  const size = 64;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = size;
  const ctx = canvas.getContext("2d");
  const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
  g.addColorStop(0, "rgba(255,255,255,1)");
  g.addColorStop(0.35, "rgba(255,255,255,.75)");
  g.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, size, size);
  glowTexture = new THREE.CanvasTexture(canvas);
  return glowTexture;
}

function renderRisk3D(rows) {
  const container = document.getElementById("risk3d");
  if (!container || typeof THREE === "undefined") return;

  if (risk3dState) {
    cancelAnimationFrame(risk3dState.rafId);
    risk3dState.renderer.dispose();
    risk3dState = null;
  }
  container.innerHTML = "";
  if (!rows.length) return;

  const width = container.clientWidth || 400;
  const height = container.clientHeight || 360;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
  camera.position.set(9, 7, 9);
  camera.lookAt(0, 0, 0);

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(width, height);
  container.appendChild(renderer.domElement);

  const group = new THREE.Group();
  scene.add(group);

  const grid = new THREE.GridHelper(12, 12, 0x3ba3ff, 0x22304a);
  grid.position.y = -5;
  grid.material.transparent = true;
  grid.material.opacity = 0.18;
  group.add(grid);

  const axes = new THREE.AxesHelper(6);
  axes.material.transparent = true;
  axes.material.opacity = 0.25;
  group.add(axes);

  const n = rows.length;
  const positions = new Float32Array(n * 3);
  const colors = new Float32Array(n * 3);
  const c = new THREE.Color();
  const JITTER = 0.8;

  rows.forEach((r, i) => {
    const key = `${r.username}|${r.date}`;
    const jx = (hash01(key + "x") - 0.5) * JITTER;
    const jy = (hash01(key + "y") - 0.5) * JITTER;
    const jz = (hash01(key + "z") - 0.5) * JITTER;
    positions[i * 3] = (r.rule_score / 100) * 10 - 5 + jx;
    positions[i * 3 + 1] = (r.anomaly_score / 100) * 10 - 5 + jy;
    positions[i * 3 + 2] = (r.final_score / 100) * 10 - 5 + jz;
    c.setHex(classColorHex(r.classification));
    colors[i * 3] = c.r;
    colors[i * 3 + 1] = c.g;
    colors[i * 3 + 2] = c.b;
  });

  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));

  const material = new THREE.PointsMaterial({
    size: 0.42,
    map: getGlowTexture(),
    vertexColors: true,
    transparent: true,
    opacity: 0.95,
    sizeAttenuation: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  group.add(new THREE.Points(geometry, material));

  // Faint ambient starfield behind the data for depth/atmosphere.
  const starCount = 140;
  const starPositions = new Float32Array(starCount * 3);
  for (let i = 0; i < starCount; i++) {
    starPositions[i * 3] = (hash01("star" + i + "x") - 0.5) * 30;
    starPositions[i * 3 + 1] = (hash01("star" + i + "y") - 0.5) * 30;
    starPositions[i * 3 + 2] = (hash01("star" + i + "z") - 0.5) * 30 - 8;
  }
  const starGeometry = new THREE.BufferGeometry();
  starGeometry.setAttribute("position", new THREE.BufferAttribute(starPositions, 3));
  const starMaterial = new THREE.PointsMaterial({
    size: 0.06,
    color: 0x3ba3ff,
    map: getGlowTexture(),
    transparent: true,
    opacity: 0.35,
    sizeAttenuation: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  group.add(new THREE.Points(starGeometry, starMaterial));

  let dragging = false, lastX = 0, lastY = 0;
  const onDown = (e) => { dragging = true; lastX = e.clientX; lastY = e.clientY; };
  const onUp = () => { dragging = false; };
  const onMove = (e) => {
    if (!dragging) return;
    const dx = e.clientX - lastX, dy = e.clientY - lastY;
    group.rotation.y += dx * 0.006;
    group.rotation.x = Math.max(-1.1, Math.min(1.1, group.rotation.x + dy * 0.006));
    lastX = e.clientX; lastY = e.clientY;
  };
  container.addEventListener("pointerdown", onDown);
  window.addEventListener("pointerup", onUp);
  window.addEventListener("pointermove", onMove);
  container.addEventListener("wheel", (e) => {
    e.preventDefault();
    const dir = camera.position.clone().normalize();
    const dist = Math.max(6, Math.min(26, camera.position.length() * (1 + e.deltaY * 0.001)));
    camera.position.copy(dir.multiplyScalar(dist));
  }, { passive: false });

  function animate() {
    if (!dragging) group.rotation.y += 0.0018;
    renderer.render(scene, camera);
    risk3dState.rafId = requestAnimationFrame(animate);
  }
  risk3dState = { renderer, rafId: 0 };
  animate();
}

async function loadRisk3D() {
  const res = await apiFetch("/api/risk_3d");
  const data = await res.json();
  renderRisk3D(data);
}

async function loadModelEval() {
  const res = await apiFetch("/api/model_eval");
  const data = await res.json();
  document.getElementById("insightPrecision").textContent = (data.precision * 100).toFixed(1) + "%";
  document.getElementById("insightRecall").textContent = (data.recall * 100).toFixed(1) + "%";
  document.getElementById("insightF1").textContent = (data.f1 * 100).toFixed(1) + "%";
  const cm = data.confusion_matrix;
  document.getElementById("cmTp").textContent = cm.tp;
  document.getElementById("cmFn").textContent = cm.fn;
  document.getElementById("cmFp").textContent = cm.fp;
  document.getElementById("cmTn").textContent = cm.tn;
  const note = document.getElementById("insightNote");
  note.textContent = data.has_ground_truth
    ? `Ground truth: rows for the seeded anomalous users (${data.ground_truth_users.join(", ")}) count as "actually anomalous" - these users still behave normally most days, so recall here is a conservative lower bound, while precision shows how rarely the model false-alarms on normal users.`
    : "No seeded ground-truth users present in the current dataset (likely a real-log upload) - evaluation metrics require the synthetic demo data.";
}

async function apiFetch(url, options) {
  const res = await fetch(url, options);
  if (res.status === 401) {
    window.location.href = "/login";
    throw new Error("Session expired");
  }
  return res;
}

async function loadSummary() {
  const res = await apiFetch("/api/summary");
  const data = await res.json();
  animateCount(document.getElementById("statUsers"), data.users);
  animateCount(document.getElementById("statEvents"), data.events, (v) => v.toLocaleString());
  animateCount(document.getElementById("statAlerts"), data.alerts);
  animateCount(document.getElementById("statHighRisk"), data.high_risk_users);
}

async function loadTimeline() {
  const res = await apiFetch("/api/timeline");
  const data = await res.json();
  const ctx = document.getElementById("timelineChart");

  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: data.labels,
      datasets: [
        {
          label: "Events / day",
          data: data.event_counts,
          borderColor: COLORS.accent,
          backgroundColor: "rgba(59,163,255,.12)",
          fill: true,
          tension: 0.3,
          pointRadius: 0,
          yAxisID: "y",
        },
        {
          label: "Anomalies / day",
          data: data.anomaly_counts,
          borderColor: COLORS.highrisk,
          backgroundColor: "rgba(239,70,87,.15)",
          fill: false,
          tension: 0.3,
          pointRadius: 2,
          yAxisID: "y1",
        },
      ],
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { labels: { color: COLORS.muted } },
      },
      scales: {
        x: { ticks: { color: COLORS.muted, maxTicksLimit: 10 }, grid: { color: "rgba(255,255,255,.05)" } },
        y: { position: "left", ticks: { color: COLORS.muted }, grid: { color: "rgba(255,255,255,.05)" } },
        y1: { position: "right", ticks: { color: COLORS.muted }, grid: { display: false } },
      },
    },
  });
}

async function loadRiskDistribution() {
  const res = await apiFetch("/api/risk_distribution");
  const data = await res.json();
  const ctx = document.getElementById("riskDonutChart");
  const counts = data.counts;

  if (donutChart) donutChart.destroy();
  donutChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Normal", "Suspicious", "High Risk"],
      datasets: [{
        data: [counts["NORMAL"], counts["SUSPICIOUS"], counts["HIGH RISK"]],
        backgroundColor: [COLORS.normal, COLORS.suspicious, COLORS.highrisk],
        borderColor: "#121a2b",
        borderWidth: 2,
      }],
    },
    options: {
      plugins: { legend: { display: false } },
      cutout: "68%",
    },
  });

  const legend = document.getElementById("riskLegend");
  const pct = data.percentages;
  legend.innerHTML = `
    <div class="d-flex justify-content-between mb-1"><span><span class="badge-risk badge-normal">NORMAL</span></span><span>${pct["NORMAL"]}% (${counts["NORMAL"]})</span></div>
    <div class="d-flex justify-content-between mb-1"><span><span class="badge-risk badge-suspicious">SUSPICIOUS</span></span><span>${pct["SUSPICIOUS"]}% (${counts["SUSPICIOUS"]})</span></div>
    <div class="d-flex justify-content-between"><span><span class="badge-risk badge-highrisk">HIGH RISK</span></span><span>${pct["HIGH RISK"]}% (${counts["HIGH RISK"]})</span></div>
  `;
}

async function loadTopSuspicious() {
  const res = await apiFetch("/api/top_suspicious?limit=10");
  const data = await res.json();
  const body = document.getElementById("topSuspiciousBody");
  if (!data.length) {
    body.innerHTML = `<tr><td colspan="4" class="text-muted">No data</td></tr>`;
    return;
  }
  body.innerHTML = data.map(u => `
    <tr class="row-link" onclick="showUser('${u.username}')">
      <td>${u.username}</td>
      <td>${u.score}</td>
      <td><span class="badge-risk ${badgeClass(u.classification)}">${u.classification}</span></td>
      <td class="text-muted">view →</td>
    </tr>
  `).join("");
}

async function loadAlerts() {
  const res = await apiFetch("/api/alerts?limit=30");
  const data = await res.json();
  const list = document.getElementById("alertsList");
  if (!data.length) {
    list.innerHTML = `<div class="text-muted">No alerts</div>`;
    return;
  }
  list.innerHTML = data.map(a => `
    <div class="alert-item ${a.severity === 'HIGH' ? 'severity-high' : 'severity-medium'}">
      <span>🚨</span>
      <span>${a.message}</span>
      <span class="alert-time">${a.date}</span>
    </div>
  `).join("");
}

async function loadAllUsers() {
  const res = await apiFetch("/api/users");
  const data = await res.json();
  const body = document.getElementById("allUsersBody");
  if (!data.length) {
    body.innerHTML = `<tr><td colspan="6" class="text-muted">No data</td></tr>`;
    return;
  }
  body.innerHTML = data.map(u => `
    <tr class="row-link" onclick="showUser('${u.username}')">
      <td>${u.username}</td>
      <td>${fmtDate(u.first_seen)}</td>
      <td>${fmtDate(u.last_seen)}</td>
      <td>${u.total_events}</td>
      <td>${u.max_score}</td>
      <td><span class="badge-risk ${badgeClass(u.classification)}">${u.classification}</span></td>
    </tr>
  `).join("");
}

function renderShapBars(historyRows) {
  const container = document.getElementById("userModalShap");
  if (!historyRows.length) { container.innerHTML = ""; return; }
  const peak = historyRows.reduce((a, b) => (b.final_score > a.final_score ? b : a), historyRows[0]);
  let features = [];
  try { features = JSON.parse(peak.shap_explanation || "[]"); } catch (e) { features = []; }
  if (!features.length) { container.innerHTML = ""; return; }

  const maxAbs = Math.max(...features.map(f => Math.abs(f.impact)), 0.001);
  container.innerHTML = `
    <h6 class="text-muted mb-2">Top contributing factors — ${peak.date} (peak day, final score ${peak.final_score})</h6>
    <div class="shap-bars">
      ${features.map(f => {
        const pct = Math.min(100, Math.abs(f.impact) / maxAbs * 100);
        const cls = f.impact >= 0 ? "positive" : "negative";
        return `
          <div class="shap-bar-row">
            <span>${f.feature}</span>
            <div class="shap-bar-track"><div class="shap-bar-fill ${cls}" style="width:${pct}%"></div></div>
            <span class="shap-bar-impact">${f.impact > 0 ? "+" : ""}${f.impact}</span>
          </div>`;
      }).join("")}
    </div>
  `;
}

async function showUser(username) {
  document.getElementById("userModalTitle").textContent = `${username} — behavior history`;
  document.getElementById("userModalBody").innerHTML = "Loading...";
  document.getElementById("userModalShap").innerHTML = "";
  const modal = new bootstrap.Modal(document.getElementById("userModal"));
  modal.show();

  const res = await apiFetch(`/api/user/${encodeURIComponent(username)}`);
  const data = await res.json();

  renderShapBars(data.history);

  const historyRows = data.history.map(h => `
    <tr>
      <td>${h.date}</td>
      <td>${h.failed_logins}</td>
      <td>${h.unusual_time_events}</td>
      <td>${h.distinct_ip_count}</td>
      <td>${h.download_count}</td>
      <td>${h.rule_score}</td>
      <td>${h.anomaly_score}</td>
      <td><strong>${h.final_score}</strong></td>
      <td><span class="badge-risk ${badgeClass(h.classification)}">${h.classification}</span></td>
    </tr>
  `).join("");

  document.getElementById("userModalBody").innerHTML = `
    <h6 class="text-muted">Daily risk history</h6>
    <div class="table-responsive mb-4">
      <table class="table ct-table table-sm">
        <thead><tr><th>Date</th><th>Failed</th><th>Unusual Time</th><th>IPs</th><th>Downloads</th><th>Rule</th><th>Anomaly</th><th>Final</th><th>Status</th></tr></thead>
        <tbody>${historyRows || '<tr><td colspan="9" class="text-muted">No history</td></tr>'}</tbody>
      </table>
    </div>
    <h6 class="text-muted">Recent raw events</h6>
    <div class="table-responsive">
      <table class="table ct-table table-sm">
        <thead><tr><th>Timestamp</th><th>Event</th><th>Status</th><th>IP</th><th>Resource</th></tr></thead>
        <tbody>
          ${data.recent_events.map(e => `
            <tr><td>${fmtDate(e.timestamp)}</td><td>${e.event_type}</td><td>${e.login_status}</td><td>${e.ip_address}</td><td>${e.resource}</td></tr>
          `).join("") || '<tr><td colspan="5" class="text-muted">No events</td></tr>'}
        </tbody>
      </table>
    </div>
  `;
}

async function loadAll() {
  await Promise.all([
    loadSummary(),
    loadRisk3D(),
    loadModelEval(),
    loadTimeline(),
    loadRiskDistribution(),
    loadTopSuspicious(),
    loadAlerts(),
    loadAllUsers(),
  ]);
  document.getElementById("lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
}

const runPipelineBtn = document.getElementById("runPipelineBtn");
if (runPipelineBtn) {
  runPipelineBtn.addEventListener("click", async () => {
    const spinner = document.getElementById("runBtnSpinner");
    const label = document.getElementById("runBtnLabel");
    runPipelineBtn.disabled = true;
    spinner.classList.remove("d-none");
    label.textContent = "Running pipeline...";
    try {
      await apiFetch("/api/run_pipeline", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ days: 30 }),
      });
      await loadAll();
    } finally {
      runPipelineBtn.disabled = false;
      spinner.classList.add("d-none");
      label.textContent = "Regenerate Logs & Analyze";
    }
  });
}

loadAll();
