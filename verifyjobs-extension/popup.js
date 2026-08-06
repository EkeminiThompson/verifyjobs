// popup.js

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let currentTab = "text";

// Tabs
$$(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach((t) => t.classList.remove("active"));
    $$(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    currentTab = btn.dataset.tab;
    $(`#${currentTab}Panel`).classList.add("active");
  });
});

$("#settingsBtn").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

$("#analyzeBtn").addEventListener("click", () => runAnalysis());
$("#newCheckBtn").addEventListener("click", resetUI);
$("#retryBtn").addEventListener("click", resetUI);

// On open: check for pending analysis from context menu / FAB
chrome.storage.session.get("pendingAnalysis", async ({ pendingAnalysis }) => {
  if (pendingAnalysis) {
    await chrome.storage.session.remove("pendingAnalysis");
    if (pendingAnalysis.type === "text") {
      currentTab = "text";
      $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === "text"));
      $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "textPanel"));
      $("#jobText").value = pendingAnalysis.text || "";
      $("#jobTitle").value = pendingAnalysis.jobTitle || "";
    } else if (pendingAnalysis.type === "url") {
      currentTab = "url";
      $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === "url"));
      $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "urlPanel"));
      $("#jobUrl").value = pendingAnalysis.url || "";
    }
    // Auto-run
    runAnalysis(pendingAnalysis);
  }
});

async function runAnalysis(prePayload = null) {
  showSection("loading");

  // Only accept a real analysis payload (must have .type)
  let payload = (prePayload && typeof prePayload === "object" && prePayload.type) ? prePayload : null;

  if (!payload) {
    if (currentTab === "text") {
      const text = $("#jobText").value.trim();
      if (text.length < 10) {
        showError("Please paste at least 10 characters of job text.");
        return;
      }
      payload = {
        type: "text",
        text,
        jobTitle: $("#jobTitle").value.trim() || "Untitled Job",
        source: "Extension"
      };
    } else if (currentTab === "url") {
      let url = $("#jobUrl").value.trim();
      if (!url) {
        showError("Please enter a URL.");
        return;
      }
      if (!/^https?:\/\//i.test(url)) url = "https://" + url;
      payload = { type: "url", url };
    } else if (currentTab === "page") {
      // Get current tab URL
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url || tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://")) {
        showError("Cannot analyze this type of page.");
        return;
      }
      payload = { type: "url", url: tab.url };
    }
  }

  try {
    const response = await chrome.runtime.sendMessage({
      action: "analyze",
      payload
    });

    if (!response?.ok) {
      throw new Error(response?.error || "Analysis failed");
    }

    renderResult(response.result);
  } catch (err) {
    showError(err.message || "Something went wrong. Is the API server running?");
  }
}

function renderResult(data) {
  showSection("result");

  const risk = data.riskScore ?? data.risk_score ?? 0;
  const legit = data.legitimacyScore ?? data.legitimacy_score ?? (100 - risk);
  const status = (data.status || data.recommendation || "").toLowerCase();

  $("#riskScore").textContent = Math.round(risk);
  $("#legitScore").textContent = Math.round(legit);

  // Color the risk box
  const riskBox = $("#riskBox");
  riskBox.style.borderColor = risk >= 70 ? "#f87171" : risk >= 45 ? "#fbbf24" : "#34d399";
  $("#riskScore").style.color = risk >= 70 ? "#dc2626" : risk >= 45 ? "#d97706" : "#059669";

  const badge = $("#statusBadge");
  badge.className = "status-badge";
  if (risk >= 70 || status.includes("danger") || status.includes("scam") || status.includes("high")) {
    badge.textContent = "High Risk";
    badge.classList.add("danger");
  } else if (risk >= 45 || status.includes("caution") || status.includes("suspicious")) {
    badge.textContent = "Caution";
    badge.classList.add("caution");
  } else {
    badge.textContent = "Lower Risk";
    badge.classList.add("safe");
  }

  $("#recommendation").textContent =
    data.recommendation ||
    data.summary ||
    data.note ||
    (risk >= 70
      ? "Multiple serious scam indicators found. Avoid this opportunity."
      : risk >= 45
      ? "Suspicious signals detected. Research the employer carefully before proceeding."
      : "Fewer red flags detected, but always verify independently.");

  // Red flags
  const redFlags = data.redFlags || data.red_flags || data.flags || [];
  const redSection = $("#redFlags");
  const redList = $("#redFlagsList");
  redList.innerHTML = "";
  if (redFlags.length) {
    redSection.classList.remove("hidden");
    redFlags.forEach((f) => {
      const li = document.createElement("li");
      li.textContent = typeof f === "string" ? f : f.label || f.message || JSON.stringify(f);
      redList.appendChild(li);
    });
  } else {
    redSection.classList.add("hidden");
  }

  // Positive signals
  const positives = data.positiveSignals || data.positive_signals || data.positives || [];
  const posSection = $("#positiveSignals");
  const posList = $("#positiveList");
  posList.innerHTML = "";
  if (positives.length) {
    posSection.classList.remove("hidden");
    positives.forEach((f) => {
      const li = document.createElement("li");
      li.textContent = typeof f === "string" ? f : f.label || f.message || JSON.stringify(f);
      posList.appendChild(li);
    });
  } else {
    posSection.classList.add("hidden");
  }

  // Meta
  const metaParts = [];
  if (data.submittedUrl) metaParts.push(`URL: ${truncate(data.submittedUrl, 40)}`);
  if (data.canonicalUrl) metaParts.push(`Canonical: ${truncate(data.canonicalUrl, 40)}`);
  if (data.ml?.available) metaParts.push("ML + Rules");
  if (data.cached) metaParts.push("Cached");
  $("#metaInfo").textContent = metaParts.join(" · ");
}

function showSection(name) {
  ["input", "loading", "result", "error"].forEach((s) => {
    $(`#${s}Section`).classList.toggle("hidden", s !== name);
  });
}

function showError(msg) {
  showSection("error");
  $("#errorMessage").textContent = msg;
}

function resetUI() {
  showSection("input");
  $("#jobText").value = "";
  $("#jobTitle").value = "";
  $("#jobUrl").value = "";
}

function truncate(str, len) {
  if (!str) return "";
  return str.length > len ? str.slice(0, len) + "…" : str;
}
