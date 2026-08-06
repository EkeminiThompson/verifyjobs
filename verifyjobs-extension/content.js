// content.js — Injects a floating "Check with VerifyJobs" button on job sites

(function () {
  if (window.__verifyJobsInjected) return;
  window.__verifyJobsInjected = true;

  // Simple job page detection heuristics
  const isLikelyJobPage = () => {
    const url = location.href.toLowerCase();
    const title = document.title.toLowerCase();
    const bodyText = document.body?.innerText?.slice(0, 2000).toLowerCase() || "";

    const jobSignals = [
      /job|career|position|vacancy|hiring|recruit|apply now|job description/i.test(title),
      /linkedin\.com\/jobs\//.test(url),
      /indeed\.com\/viewjob|indeed\.com\/jobs/.test(url),
      /glassdoor\.com\/job/.test(url),
      bodyText.includes("job description") || bodyText.includes("responsibilities") || bodyText.includes("requirements")
    ];
    return jobSignals.filter(Boolean).length >= 1;
  };

  function createFloatingButton() {
    if (document.getElementById("verifyjobs-fab")) return;

    const btn = document.createElement("button");
    btn.id = "verifyjobs-fab";
    btn.title = "Check this job with VerifyJobs";
    btn.innerHTML = `
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M9 12l2 2 4-4"/>
        <circle cx="12" cy="12" r="10"/>
      </svg>
      <span>VerifyJobs</span>
    `;
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.classList.add("loading");

      try {
        // Prefer selected text, otherwise extract page content / URL
        const selection = window.getSelection()?.toString().trim();
        let payload;

        if (selection && selection.length > 30) {
          payload = {
            type: "text",
            text: selection.slice(0, 50000),
            jobTitle: document.title.slice(0, 120) || "Selected text",
            source: location.hostname
          };
        } else {
          // Send the current page URL (server will fetch & analyze)
          payload = {
            type: "url",
            url: location.href
          };
        }

        await chrome.storage.session.set({ pendingAnalysis: payload });
        // Open popup
        chrome.runtime.sendMessage({ action: "openPopup" }).catch(() => {});
        // Also try to open the extension popup
        chrome.action?.openPopup?.().catch(() => {
          // Fallback: just store and let user click the icon
          alert("Data ready. Click the VerifyJobs extension icon to see results.");
        });
      } catch (err) {
        console.error("VerifyJobs FAB error:", err);
      } finally {
        btn.disabled = false;
        btn.classList.remove("loading");
      }
    });

    document.body.appendChild(btn);
  }

  // Extract cleaner job text from common job boards (optional enhancement)
  function extractJobText() {
    // LinkedIn
    const linkedinDesc = document.querySelector(".jobs-description__content, .jobs-box__html-content, .description__text");
    if (linkedinDesc) return linkedinDesc.innerText;

    // Indeed
    const indeedDesc = document.querySelector("#jobDescriptionText, .jobsearch-jobDescriptionText");
    if (indeedDesc) return indeedDesc.innerText;

    // Glassdoor
    const gd = document.querySelector("[data-test='description'], .jobDescriptionContent");
    if (gd) return gd.innerText;

    // Generic
    const main = document.querySelector("main, article, [role='main']");
    if (main) return main.innerText.slice(0, 15000);

    return document.body.innerText.slice(0, 10000);
  }

  // Expose extractor for popup if needed
  window.__verifyJobsExtract = extractJobText;

  if (isLikelyJobPage()) {
    // Small delay so page settles
    setTimeout(createFloatingButton, 1200);
  }

  // Re-check on SPA navigation (LinkedIn etc.)
  let lastUrl = location.href;
  const observer = new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      document.getElementById("verifyjobs-fab")?.remove();
      if (isLikelyJobPage()) {
        setTimeout(createFloatingButton, 1500);
      }
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
