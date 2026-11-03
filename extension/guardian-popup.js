
"use strict";

const guardianMode = document.getElementById("guardian-mode");

const guardianApprove = document.getElementById("guardian-approve");

const guardianRevokeBroad = document.getElementById("guardian-revoke-broad");

const guardianStatus = document.getElementById("guardian-status");

const guardianAssessmentStatus = document.getElementById("guardian-assessment-status");

const guardianResult = document.getElementById("guardian-result");

const BROAD_ORIGINS = ["http://*/*", "https://*/*"];

let guardianState = {

  mode: "OFF",

  enabled: false,

  origins: [],

  allBroadGranted: false

};

let refreshRevision = 0;

let updatingMode = false;

async function guardianRequest(message) {

  const response = await chrome.runtime.sendMessage(message);

  if (response?.error) {

    throw new Error(response.error);

  }

  return response;

}

async function refreshGuardian() {

  const revision = ++refreshRevision;

  const state = await guardianRequest({

    type: "guardian-state",

    tabId: currentTabId,

    url: currentUrl

  });

  if (revision !== refreshRevision) return;

  guardianState = state;

  const mode = state.mode || "OFF";

  const origin = Guardian.origin(currentUrl);

  document.getElementById("guardian-state").textContent = mode;

  guardianMode.value = mode;

  guardianMode.disabled = updatingMode;

  guardianApprove.hidden =

    mode !== "SELECTED_WEBSITES" ||

    !origin ||

    state.origins.includes(origin);

  const broadGranted = await chrome.permissions.contains({

    origins: BROAD_ORIGINS

  });

  if (revision !== refreshRevision) return;

  guardianRevokeBroad.hidden = !broadGranted;

  const list = document.getElementById("guardian-origins");

  list.replaceChildren();

  for (const approved of state.origins) {

    const item = document.createElement("li");

    item.append(document.createTextNode(approved + " "));

    const revoke = document.createElement("button");

    revoke.type = "button";

    revoke.textContent = "Revoke monitoring";

    revoke.addEventListener("click", async () => {

      try {

        await guardianRequest({

          type: "guardian-revoke",

          origin: approved

        });

        guardianStatus.textContent =

          "Website monitoring permission revoked.";

        await refreshGuardian();

      } catch (error) {

        guardianStatus.textContent =

          error.message || "Could not revoke monitoring.";

      }

    });

    item.append(revoke);

    list.append(item);

  }

  if (!state.origins.length) {

    const item = document.createElement("li");

    item.textContent = "None. No individually approved websites.";

    list.append(item);

  }

  guardianResult.hidden = true;

  if (state.result?.data) {

    renderResult(state.result.data, "guardian-");

    guardianAssessmentStatus.textContent =

      state.result.warningError ||

      "Latest automatic assessment for this URL.";

  } else if (state.result?.error) {

    guardianAssessmentStatus.textContent = state.result.error;

  } else if (mode === "OFF") {

    guardianAssessmentStatus.textContent =

      "Guardian Mode is OFF. Manual analysis remains available.";

  } else if (mode === "ALL_WEBSITES") {

    guardianAssessmentStatus.textContent =

      "Universal monitoring is active. Reload or navigate to trigger analysis.";

  } else if (!origin || !state.origins.includes(origin)) {

    guardianAssessmentStatus.textContent =

      "This website is not approved for monitoring.";

  } else {

    guardianAssessmentStatus.textContent =

      "No automatic assessment yet. Reload or navigate on this website.";

  }

}

async function approveCurrentWebsite() {

  const origin = Guardian.origin(currentUrl);

  if (!origin) return;

  const granted = await chrome.permissions.request({

    origins: [Guardian.pattern(origin)]

  });

  if (!granted) {

    guardianStatus.textContent =

      "Permission declined. This website will not be monitored.";

    return;

  }

  await guardianRequest({

    type: "guardian-enable",

    url: currentUrl

  });

  guardianStatus.textContent =

    `Monitoring approved for ${origin}. Reload or navigate to start analysis.`;

}

guardianMode.addEventListener("change", async () => {

  if (updatingMode) return;

  const requestedMode = guardianMode.value;

  const previousMode = guardianState.mode;

  updatingMode = true;

  guardianMode.disabled = true;

  try {

    if (requestedMode === "ALL_WEBSITES") {

      const granted = await chrome.permissions.request({

        origins: BROAD_ORIGINS

      });

      if (!granted) {

        guardianStatus.textContent =

          "Broad permission declined. Previous mode preserved.";

        guardianMode.value = previousMode;

        return;

      }

    }

    await guardianRequest({

      type: "guardian-set-mode",

      mode: requestedMode

    });

    guardianStatus.textContent =

      requestedMode === "OFF"

        ? "Guardian Mode is OFF. Manual analysis remains available."

        : requestedMode === "SELECTED_WEBSITES"

          ? "Selected Websites mode activated."

          : "All Websites mode activated.";

    await refreshGuardian();

  } catch (error) {

    guardianMode.value = previousMode;

    guardianStatus.textContent =

      error.message || "Could not change Guardian Mode.";

  } finally {

    updatingMode = false;

    guardianMode.disabled = false;

  }

});

guardianApprove.addEventListener("click", async () => {

  try {

    await approveCurrentWebsite();

    await refreshGuardian();

  } catch (error) {

    guardianStatus.textContent =

      error.message || "Website permission could not be approved.";

  }

});

guardianRevokeBroad.addEventListener("click", async () => {

  try {

    await guardianRequest({

      type: "guardian-revoke-broad"

    });

    guardianStatus.textContent =

      "All-websites permission revoked. Selected Websites mode activated.";

    await refreshGuardian();

  } catch (error) {

    guardianStatus.textContent =

      error.message || "Could not revoke broad permission.";

  }

});

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

    guardianAssessmentStatus.textContent =

      "Automatic assessment unavailable. Reopen the popup.";

  });

});

chrome.storage.onChanged.addListener((changes, area) => {

  if (

    (area === "session" && changes.results) ||

    (area === "local" &&

      (changes.guardianEnabled ||

       changes.guardianMode ||

       changes.approvedOrigins ||

       changes.allBroadGranted))

  ) {

    void currentTabReady.then(refreshGuardian).catch(() => {

      guardianAssessmentStatus.textContent =

        "Automatic assessment unavailable. Reopen the popup.";

    });

  }

});

currentTabReady.then(refreshGuardian).catch(() => {

  guardianStatus.textContent =

    "Guardian settings unavailable. Manual analysis still works.";

});
