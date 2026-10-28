"use strict";

const endpoint = "http://127.0.0.1:8000/analyze-url";
const urlDisplay = document.getElementById("current-url");
const analyzeButton = document.getElementById("analyze");
const status = document.getElementById("status");
const result = document.getElementById("result");
let currentUrl = null;
let currentTabId = null;

async function loadCurrentTab() {
  currentUrl = null;
  currentTabId = null;
  analyzeButton.disabled = true;
  try {
    // activeTab grants URL access after the user opens this popup.
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) {
      urlDisplay.textContent = "URL unavailable.";
      status.textContent = "Cannot analyze this tab.";
      return;
    }

    const parsed = new URL(tab.url);
    // Never send URLs containing embedded usernames or passwords.
    if (parsed.username || parsed.password) {
      urlDisplay.textContent = "URL hidden because it contains credentials.";
      status.textContent = "URLs with embedded credentials cannot be analyzed.";
      return;
    }

    urlDisplay.textContent = tab.url;
    if (!["http:", "https:"].includes(parsed.protocol)) {
      status.textContent = "Only HTTP and HTTPS pages can be analyzed.";
      return;
    }

    currentTabId = tab.id;
    currentUrl = tab.url;
    analyzeButton.disabled = false;
  } catch {
    urlDisplay.textContent = "URL unavailable.";
    status.textContent = "Cannot analyze this tab.";
  }
}

analyzeButton.addEventListener("click", async () => {
  if (!currentUrl || analyzeButton.disabled) return;

  analyzeButton.disabled = true;
  result.hidden = true;
  status.textContent = "Analyzing…";

  try {
    let response;
    try {
      response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentUrl }),
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
        signal: AbortSignal.timeout(10000),
      });
    } catch {
      status.textContent = "SUS.NOT backend is offline.";
      return;
    }

    if (!response.ok) {
      status.textContent = response.status === 422
        ? "The backend could not accept this URL."
        : "The backend could not complete the analysis. Please try again.";
      return;
    }

    const data = await response.json();
    if (!Number.isInteger(data.sus_score) || data.sus_score < 0 ||
        data.sus_score > 100 ||
        !["low", "review", "high", "critical"].includes(data.risk_level) ||
        !Array.isArray(data.indicators) ||
        !data.indicators.every((item) => typeof item === "string") ||
        typeof data.message !== "string") {
      throw new Error("Unexpected response format");
    }

    renderResult(data);
    status.textContent = "Analysis complete.";
  } catch {
    status.textContent = "The backend returned an unexpected response.";
  } finally {
    analyzeButton.disabled = false;
  }
});

function renderResult(data, prefix = "") {
  // Treat all backend output as text, never as HTML.
  document.getElementById(`${prefix}score`).textContent = `${data.sus_score} / 100`;
  document.getElementById(`${prefix}risk`).textContent = data.risk_level;
  const indicators = document.getElementById(`${prefix}indicators`);
  indicators.replaceChildren();
  for (const indicator of data.indicators.length ? data.indicators : ["None detected."]) {
    const item = document.createElement("li");
    item.textContent = indicator;
    indicators.appendChild(item);
  }
  document.getElementById(`${prefix}message`).textContent = data.message;
  document.getElementById(`${prefix}result`).hidden = false;
}

const currentTabReady = loadCurrentTab();
