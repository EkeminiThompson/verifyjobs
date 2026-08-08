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

const settingsBtn = $("#settingsBtn");
if (settingsBtn) {
  settingsBtn.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
}

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
    } else if (currentTab === "file") {
      const fileInput = $("#jobFile");
      const file = fileInput?.files?.[0];
      if (!file) {
        showError("Please choose a PDF, Word document, or image.");
        return;
      }
      if (file.size > 10 * 1024 * 1024) {
        showError("File too large (max 10 MB).");
        return;
      }
      payload = { type: "file", file };
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

  // Decision layer (server-provided or client-side fallback)
  // Always prefer server decision; rebuild locally if status is not_a_job
  let decision = data.decision || null;
  if (!decision && globalThis.VerifyJobsDecision) {
    decision = globalThis.VerifyJobsDecision.buildDecision(data);
  }

  // Verdict card (null-safe for older sidepanel markup)
  const verdictCard = $("#verdictCard");
  const verdictLabel = $("#verdictLabel");
  const verdictSummary = $("#verdictSummary");
  const patternEl = $("#scamPattern");

  if (decision && verdictLabel) {
    verdictLabel.textContent = decision.verdictLabel;
    if (verdictSummary) verdictSummary.textContent = decision.summary;
    if (verdictCard) verdictCard.className = "verdict-card tone-" + (decision.verdictTone || "warn");
    if (patternEl) {
      if (decision.scamPattern) {
        patternEl.textContent = "Looks like: " + decision.scamPattern.label;
        patternEl.classList.remove("hidden");
      } else {
        patternEl.classList.add("hidden");
      }
    }
    const reasonsList = $("#reasonsList");
    if (reasonsList) {
      reasonsList.innerHTML = "";
      (decision.topReasons || []).forEach((r) => {
        const li = document.createElement("li");
        li.textContent = r;
        reasonsList.appendChild(li);
      });
    }
    const stepsList = $("#nextStepsList");
    if (stepsList) {
      stepsList.innerHTML = "";
      (decision.nextSteps || []).forEach((s) => {
        const li = document.createElement("li");
        li.textContent = s;
        stepsList.appendChild(li);
      });
    }
  } else if (verdictLabel) {
    const st = String(data.status || "").toLowerCase();
    if (st === "not_a_job") {
      verdictLabel.textContent = "Not a job posting";
      if (verdictSummary) verdictSummary.textContent = data.explanation || data.recommendation || "This does not look like a job ad.";
      if (verdictCard) verdictCard.className = "verdict-card tone-neutral";
    } else {
      verdictLabel.textContent = risk >= 70 ? "Don't apply" : risk >= 45 ? "Verify first" : "Looks OK";
      if (verdictSummary) verdictSummary.textContent = data.recommendation || "";
      if (verdictCard) verdictCard.className = "verdict-card tone-" + (risk >= 70 ? "danger" : risk >= 45 ? "warn" : "safe");
    }
    if (patternEl) patternEl.classList.add("hidden");
  }

  // Legacy sidepanel status badge (if present)
  const statusBadge = $("#statusBadge");
  if (statusBadge) {
    if (decision) statusBadge.textContent = decision.verdictLabel;
    else if (String(data.status || "").toLowerCase() === "not_a_job") statusBadge.textContent = "Not a job posting";
    else statusBadge.textContent = data.statusLabel || data.status || "—";
  }
  const recEl = $("#recommendation");
  if (recEl) {
    recEl.textContent = (decision && decision.summary) || data.recommendation || data.explanation || "";
  }

  const isNotJob =
    (decision && decision.verdict === "not_applicable") ||
    String(data.status || "").toLowerCase() === "not_a_job" ||
    data.metadata?.notAJob === true;

  if (isNotJob) {
    $("#riskScore").textContent = "N/A";
    $("#legitScore").textContent = "N/A";
    $("#riskScore").style.color = "#6b7280";
    $("#legitScore").style.color = "#6b7280";
    $("#riskBox").style.borderColor = "#d1d5db";
    if ($("#legitBox")) $("#legitBox").style.borderColor = "#d1d5db";
  } else {
    $("#riskScore").textContent = Math.round(risk);
    $("#legitScore").textContent = Math.round(legit);
    $("#riskScore").style.color = risk >= 70 ? "#dc2626" : risk >= 45 ? "#d97706" : "#059669";
    $("#legitScore").style.color = "";
    $("#riskBox").style.borderColor = risk >= 70 ? "#f87171" : risk >= 45 ? "#fbbf24" : "#34d399";
    if ($("#legitBox")) $("#legitBox").style.borderColor = "";
  }

  // Full red flags (secondary)
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

  const positives = data.positiveIndicators || data.positiveSignals || data.positive_signals || data.positives || [];
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

  const metaParts = [];
  if (data.submittedUrl) metaParts.push("URL: " + truncate(data.submittedUrl, 40));
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
  if ($("#jobFile")) $("#jobFile").value = "";
  if ($("#fileLabel")) $("#fileLabel").textContent = "PDF, Word, or image (jpg/png/webp)";
}

function truncate(str, len) {
  if (!str) return "";
  return str.length > len ? str.slice(0, len) + "…" : str;
}
