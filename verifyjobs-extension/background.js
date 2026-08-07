// background.js — Service worker for VerifyJobs Chrome extension

const DEFAULT_API_BASE = "https://verifyjobs.org";

// Create context menu on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "verifyjobs-check-selection",
    title: "Check selection with VerifyJobs",
    contexts: ["selection"]
  });
  chrome.contextMenus.create({
    id: "verifyjobs-check-page",
    title: "Check this page with VerifyJobs",
    contexts: ["page", "link"]
  });
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});
});

// Context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;

  let payload = {};

  if (info.menuItemId === "verifyjobs-check-selection" && info.selectionText) {
    payload = {
      type: "text",
      text: info.selectionText.trim().slice(0, 50000),
      jobTitle: "Selected text",
      source: "Context Menu"
    };
  } else if (info.menuItemId === "verifyjobs-check-page") {
    const url = info.linkUrl || info.pageUrl || tab.url;
    payload = {
      type: "url",
      url: url
    };
  }

  // Store payload so popup / sidepanel can pick it up
  await chrome.storage.session.set({ pendingAnalysis: payload });

  // Open the popup (or side panel)
  try {
    await chrome.action.openPopup();
  } catch (e) {
    // Fallback: open side panel
    chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
  }
});

// Message handler from content script or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyze") {
    handleAnalyze(message.payload)
      .then(result => sendResponse({ ok: true, result }))
      .catch(err => sendResponse({ ok: false, error: err.message || String(err) }));
    return true; // async
  }

  if (message.action === "getApiBase") {
    chrome.storage.sync.get({ apiBase: DEFAULT_API_BASE }, (data) => {
      sendResponse({ apiBase: data.apiBase });
    });
    return true;
  }
});

async function handleAnalyze(payload) {
  const { apiBase } = await chrome.storage.sync.get({ apiBase: DEFAULT_API_BASE });
  const base = (apiBase || DEFAULT_API_BASE).replace(/\/$/, "");

  let endpoint, body, headers = { "Content-Type": "application/json" };

  if (payload.type === "url") {
    endpoint = `${base}/analyze-url`;
    body = JSON.stringify({ url: payload.url });
  } else if (payload.type === "text") {
    endpoint = `${base}/analyze`;
    body = JSON.stringify({
      text: payload.text,
      jobTitle: payload.jobTitle || "Untitled Job",
      source: payload.source || "Extension"
    });
  } else if (payload.type === "file") {
    endpoint = `${base}/analyze-file`;
    const fd = new FormData();
    fd.append("file", payload.file, payload.file.name || "upload");
    fd.append("jobTitle", payload.jobTitle || payload.file.name || "File Upload");
    headers = {}; // let browser set multipart boundary
    body = fd;
  } else {
    throw new Error("Unknown analysis type");
  }

  const res = await fetch(endpoint, {
    method: "POST",
    headers,
    body
  });

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(errBody.error || errBody.message || `HTTP ${res.status}`);
  }

  return await res.json();
}
