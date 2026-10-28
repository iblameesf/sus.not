"use strict";

const guardianToggle = document.getElementById("guardian-toggle");
const guardianApprove = document.getElementById("guardian-approve");
const guardianStatus = document.getElementById("guardian-status");
let guardianState = { enabled: false, origins: [] };
const guardianAssessmentStatus = document.getElementById("guardian-assessment-status");
const guardianResult = document.getElementById("guardian-result");
let refreshRevision = 0;

async function guardianRequest(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (response?.error) throw new Error(response.error);
  return response;
}

async function refreshGuardian() {
  const requestRevision = ++refreshRevision;
  const state = await guardianRequest({ type: "guardian-state", tabId: currentTabId, url: currentUrl });
  if (requestRevision !== refreshRevision) return;
  guardianState = state;
  document.getElementById("guardian-state").textContent = guardianState.enabled ? "ON" : "OFF";
  guardianToggle.textContent = guardianState.enabled ? "Turn Guardian Mode OFF" : "Enable Guardian for this website";
  guardianToggle.disabled = !guardianState.enabled && !currentUrl;
  const origin = Guardian.origin(currentUrl);
  guardianApprove.hidden = !guardianState.enabled || !origin || guardianState.origins.includes(origin);
  const list = document.getElementById("guardian-origins");
  list.replaceChildren();
  for (const approved of guardianState.origins) {
    const item = document.createElement("li");
    item.append(document.createTextNode(approved + " "));
    const revoke = document.createElement("button");
    revoke.type = "button";
    revoke.textContent = "Revoke monitoring";
    revoke.addEventListener("click", async () => {
      try {
        await guardianRequest({ type: "guardian-revoke", origin: approved });
        guardianStatus.textContent = "Website monitoring permission revoked.";
        await refreshGuardian();
      } catch {
        guardianStatus.textContent = "Could not revoke monitoring. Please retry.";
      }
    });
    item.append(revoke);
    list.append(item);
  }
  if (!guardianState.origins.length) {
    const item = document.createElement("li");
    item.textContent = "None. No websites are monitored.";
    list.append(item);
  }
  guardianResult.hidden = true;
  if (guardianState.result?.data) {
    renderResult(guardianState.result.data, "guardian-");
    guardianAssessmentStatus.textContent = guardianState.result.warningError || "Latest automatic assessment for this URL.";
  } else if (guardianState.result?.error) {
    guardianAssessmentStatus.textContent = guardianState.result.error;
  } else if (!guardianState.enabled) {
    guardianAssessmentStatus.textContent = "Guardian Mode is OFF. Manual analysis is still available.";
  } else if (!origin || !guardianState.origins.includes(origin)) {
    guardianAssessmentStatus.textContent = "This website is not approved for monitoring.";
  } else {
    guardianAssessmentStatus.textContent = "No automatic assessment for this URL yet. Reload or navigate on this approved website.";
  }
}

// Called directly from the click handler: Chrome requires a user gesture.
async function approveCurrentWebsite() {
  const origin = Guardian.origin(currentUrl);
  if (!origin) return;
  const granted = await chrome.permissions.request({ origins: [Guardian.pattern(origin)] });
  if (!granted) {
    guardianStatus.textContent = "Permission declined. This website will not be monitored.";
    return;
  }
  await guardianRequest({ type: "guardian-enable", url: currentUrl });
  guardianStatus.textContent = `Monitoring approved for ${origin}. Analysis starts on the next navigation or reload.`;
}

guardianToggle.addEventListener("click", async () => {
  guardianToggle.disabled = true;
  try {
    if (guardianState.enabled) {
      await guardianRequest({ type: "guardian-disable" });
      guardianStatus.textContent = "Guardian Mode is OFF. Manual analysis remains available.";
    } else {
      await approveCurrentWebsite();
    }
    await refreshGuardian();
  } catch {
    guardianStatus.textContent = "Could not update Guardian Mode. Please retry.";
  } finally {
    guardianToggle.disabled = !guardianState.enabled && !currentUrl;
  }
});
guardianApprove.addEventListener("click", async () => {
  try {
    await approveCurrentWebsite();
    await refreshGuardian();
  } catch {
    guardianStatus.textContent = "Website permission could not be approved. Please retry.";
  }
});

// Keep the active URL in sync if the popup is kept open (e.g. in DevTools).
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (tabId !== currentTabId || !(change.url || change.status)) return;
  void currentTabReady.then(async () => {
    const previousUrl = currentUrl;
    await loadCurrentTab();
    if (previousUrl !== currentUrl) {
      result.hidden = true;
      status.textContent = "";
    }
    await refreshGuardian();
  }).catch(() => {
    guardianAssessmentStatus.textContent = "Automatic assessment is unavailable. Reopen the popup to retry.";
  });
});

// Update a popup left open while an automatic request finishes.
chrome.storage.onChanged.addListener((changes, area) => {
  if ((area === "session" && changes.results) ||
      (area === "local" && (changes.guardianEnabled || changes.approvedOrigins))) {
    void currentTabReady.then(refreshGuardian).catch(() => {
      guardianAssessmentStatus.textContent = "Automatic assessment is unavailable. Reopen the popup to retry.";
    });
  }
});
currentTabReady.then(refreshGuardian).catch(() => {
  guardianStatus.textContent = "Guardian settings are unavailable. Manual analysis still works.";
});
