const DEFAULT_API_BASE = "http://localhost:3000";

document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.sync.get({ apiBase: DEFAULT_API_BASE }, (data) => {
    document.getElementById("apiBase").value = data.apiBase;
  });

  document.getElementById("saveBtn").addEventListener("click", () => {
    const apiBase = document.getElementById("apiBase").value.trim().replace(/\/$/, "") || DEFAULT_API_BASE;
    chrome.storage.sync.set({ apiBase }, () => {
      const status = document.getElementById("status");
      status.textContent = "Saved.";
      setTimeout(() => (status.textContent = ""), 2000);
    });
  });
});
