// popup.js — VerifyJobs extension v1.3.5

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let currentTab = "text";

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
  settingsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
}

$("#analyzeBtn")?.addEventListener("click", () => runAnalysis());
$("#newCheckBtn")?.addEventListener("click", resetUI);
$("#retryBtn")?.addEventListener("click", resetUI);

// Show selected file name
const jobFile = $("#jobFile");
if (jobFile) {
  jobFile.addEventListener("change", () => {
    const f = jobFile.files?.[0];
    const label = $("#fileLabel");
    if (!label) return;
    if (f) {
      const kb = (f.size / 1024).toFixed(1);
      label.textContent = `${f.name} (${kb} KB)`;
    } else {
      label.textContent = "PDF, Word, or image (jpg/png/webp)";
    }
  });
}

chrome.storage.session.get("pendingAnalysis", async ({ pendingAnalysis }) => {
  if (!pendingAnalysis) return;
  await chrome.storage.session.remove("pendingAnalysis");
  if (pendingAnalysis.type === "text") {
    currentTab = "text";
    $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === "text"));
    $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "textPanel"));
    if ($("#jobText")) $("#jobText").value = pendingAnalysis.text || "";
    if ($("#jobTitle")) $("#jobTitle").value = pendingAnalysis.jobTitle || "";
  } else if (pendingAnalysis.type === "url") {
    currentTab = "url";
    $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === "url"));
    $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "urlPanel"));
    if ($("#jobUrl")) $("#jobUrl").value = pendingAnalysis.url || "";
  }
  runAnalysis(pendingAnalysis);
});

async function getApiBase() {
  const { apiBase } = await chrome.storage.sync.get({ apiBase: "https://verifyjobs.org" });
  return String(apiBase || "https://verifyjobs.org").replace(/\/$/, "");
}

/**
 * File/image uploads must run in the popup (FormData + File).
 * chrome.runtime.sendMessage cannot reliably carry File objects to the service worker.
 */
async function analyzeFileDirect(file, jobTitle) {
  const base = await getApiBase();
  const fd = new FormData();
  fd.append("file", file, file.name || "upload");
  fd.append("jobTitle", jobTitle || file.name || "File Upload");
  const res = await fetch(`${base}/analyze-file`, { method: "POST", body: fd });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(errBody.error || errBody.message || `HTTP ${res.status}`);
  }
  return res.json();
}

async function runAnalysis(prePayload = null) {
  showSection("loading");

  let payload =
    prePayload && typeof prePayload === "object" && prePayload.type ? prePayload : null;

  if (!payload) {
    if (currentTab === "text") {
      const text = $("#jobText")?.value.trim() || "";
      if (text.length < 10) {
        showError("Please paste at least 10 characters of job text.");
        return;
      }
      payload = {
        type: "text",
        text,
        jobTitle: $("#jobTitle")?.value.trim() || "Untitled Job",
        source: "Extension",
      };
    } else if (currentTab === "url") {
      let url = $("#jobUrl")?.value.trim() || "";
      if (!url) {
        showError("Please enter a URL.");
        return;
      }
      if (!/^https?:\/\//i.test(url)) url = "https://" + url;
      payload = { type: "url", url };
    } else if (currentTab === "file") {
      const file = $("#jobFile")?.files?.[0];
      if (!file) {
        showError("Please choose a PDF, Word document, or image.");
        return;
      }
      if (file.size > 10 * 1024 * 1024) {
        showError("File too large (max 10 MB).");
        return;
      }
      const allowed = /\.(pdf|doc|docx|jpg|jpeg|png|webp)$/i;
      if (!allowed.test(file.name) && !String(file.type || "").startsWith("image/")) {
        showError("Only PDF, Word (.doc/.docx), or images (jpg/png/webp) are supported.");
        return;
      }
      try {
        const result = await analyzeFileDirect(file, file.name);
        renderResult(result);
      } catch (err) {
        showError(err.message || "File analysis failed. Images need OCR on the server.");
      }
      return;
    } else if (currentTab === "page") {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url || /^(chrome|chrome-extension|edge|about):/i.test(tab.url)) {
        showError("Cannot analyze this type of page.");
        return;
      }
      payload = { type: "url", url: tab.url };
    }
  }

  // If pending payload was a file (shouldn't happen via context menu), handle
  if (payload?.type === "file" && payload.file) {
    try {
      const result = await analyzeFileDirect(payload.file, payload.jobTitle);
      renderResult(result);
    } catch (err) {
      showError(err.message || "File analysis failed.");
    }
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      action: "analyze",
      payload,
    });
    if (!response?.ok) throw new Error(response?.error || "Analysis failed");
    renderResult(response.result);
  } catch (err) {
    showError(err.message || "Something went wrong. Is the API server reachable?");
  }
}

function renderResult(data) {
  showSection("result");

  const risk = data.riskScore ?? data.risk_score ?? 0;
  const legit = data.legitimacyScore ?? data.legitimacy_score ?? null;

  let decision = data.decision || null;
  if (!decision && globalThis.VerifyJobsDecision) {
    decision = globalThis.VerifyJobsDecision.buildDecision(data);
  }

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
      if (verdictSummary) verdictSummary.textContent = data.explanation || "This does not look like a job ad.";
      if (verdictCard) verdictCard.className = "verdict-card tone-neutral";
    } else if (st === "insufficient_data") {
      verdictLabel.textContent = "Could not read page";
      if (verdictSummary) verdictSummary.textContent = data.explanation || "Not enough text to score.";
      if (verdictCard) verdictCard.className = "verdict-card tone-neutral";
    } else {
      // Align with engine: ≥65 = don't apply
      verdictLabel.textContent = risk >= 65 ? "Don't apply" : risk >= 45 ? "Verify first" : "Looks OK";
      if (verdictSummary) verdictSummary.textContent = data.recommendation || "";
      if (verdictCard)
        verdictCard.className =
          "verdict-card tone-" + (risk >= 65 ? "danger" : risk >= 45 ? "warn" : "safe");
    }
    if (patternEl) patternEl.classList.add("hidden");
  }

  const statusBadge = $("#statusBadge");
  if (statusBadge) {
    if (decision) statusBadge.textContent = decision.verdictLabel;
    else statusBadge.textContent = data.statusLabel || data.status || "—";
  }

  const recEl = $("#recommendation");
  if (recEl) {
    recEl.textContent = (decision && decision.summary) || data.recommendation || data.explanation || "";
  }

  const isNotJob =
    (decision && (decision.verdict === "not_applicable" || decision.verdict === "not_a_job")) ||
    String(data.status || "").toLowerCase() === "not_a_job" ||
    data.metadata?.notAJob === true;
  const isInsufficient =
    String(data.status || "").toLowerCase() === "insufficient_data" ||
    data.metadata?.insufficientData === true;

  if (isNotJob || isInsufficient) {
    if ($("#riskScore")) {
      $("#riskScore").textContent = "N/A";
      $("#riskScore").style.color = "#6b7280";
    }
    if ($("#legitScore")) {
      $("#legitScore").textContent = "N/A";
      $("#legitScore").style.color = "#6b7280";
    }
  } else {
    if ($("#riskScore")) {
      $("#riskScore").textContent = String(risk);
      $("#riskScore").style.color = risk >= 65 ? "#d93025" : risk >= 45 ? "#e37400" : "#1a7a45";
    }
    if ($("#legitScore")) {
      if (legit == null) {
        $("#legitScore").textContent = "N/A";
        $("#legitScore").style.color = "#6b7280";
      } else {
        $("#legitScore").textContent = String(legit);
        $("#legitScore").style.color = legit >= 70 ? "#1a7a45" : legit >= 45 ? "#e37400" : "#d93025";
      }
    }
  }

  // All red flags (optional section)
  const redWrap = $("#redFlags");
  const redList = $("#redFlagsList");
  if (redList) {
    redList.innerHTML = "";
    const flags = data.redFlags || [];
    if (flags.length) {
      flags.forEach((f) => {
        const li = document.createElement("li");
        li.textContent = typeof f === "string" ? f : f.signal || f.label || String(f);
        redList.appendChild(li);
      });
      if (redWrap) redWrap.classList.remove("hidden");
    } else if (redWrap) {
      redWrap.classList.add("hidden");
    }
  }

  const posWrap = $("#positiveSignals");
  const posList = $("#positiveList");
  if (posList) {
    posList.innerHTML = "";
    const pos = data.positiveIndicators || [];
    if (pos.length) {
      pos.forEach((p) => {
        const li = document.createElement("li");
        li.textContent = typeof p === "string" ? p : p.signal || p.label || String(p);
        posList.appendChild(li);
      });
      if (posWrap) posWrap.classList.remove("hidden");
    } else if (posWrap) {
      posWrap.classList.add("hidden");
    }
  }

  const meta = $("#metaInfo");
  if (meta) {
    const bits = [];
    if (data.filename) bits.push("File: " + data.filename);
    if (data.extractedLength) bits.push(data.extractedLength + " chars extracted");
    if (data.ml?.available) bits.push("ML " + (data.ml.score ?? "—") + "%");
    else if (data.ml?.available === false) bits.push("Rules only");
    meta.textContent = bits.join(" · ");
  }

  const mlBar = $("#mlBar");
  if (mlBar) {
    if (data.ml?.available) {
      mlBar.textContent = `ML ${data.ml.score ?? "—"}% · ${data.ml.blendMethod || "blend"}`;
      mlBar.classList.remove("hidden");
    } else if (data.ml?.available === false) {
      mlBar.textContent = "ML offline — rules only";
      mlBar.classList.remove("hidden");
    } else {
      mlBar.classList.add("hidden");
    }
  }
}

function showSection(name) {
  // name: input | loading | result | error
  const map = {
    form: "inputSection",
    input: "inputSection",
    loading: "loadingSection",
    result: "resultSection",
    error: "errorSection",
  };
  const target = map[name] || name;
  ["inputSection", "loadingSection", "resultSection", "errorSection"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("hidden", id !== target);
  });
}

function showError(msg) {
  showSection("error");
  const el = $("#errorMessage");
  if (el) el.textContent = msg;
}

function resetUI() {
  showSection("input");
  if ($("#jobText")) $("#jobText").value = "";
  if ($("#jobUrl")) $("#jobUrl").value = "";
  if ($("#jobFile")) $("#jobFile").value = "";
  if ($("#fileLabel")) $("#fileLabel").textContent = "PDF, Word, or image (jpg/png/webp)";
}
