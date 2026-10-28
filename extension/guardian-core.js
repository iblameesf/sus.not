"use strict";

// Shared policy helpers. No page content is accessed.
globalThis.Guardian = {
  threshold: 60,
  suppressionMs: 5 * 60 * 1000,
  origin(url) {
    try {
      const parsed = new URL(url);
      if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) return null;
      return parsed.origin;
    } catch {
      return null;
    }
  },
  pattern(origin) {
    const url = new URL(origin);
    // Chrome host permissions cover all ports; policy still checks exact origins.
    return `${url.protocol}//${url.hostname}/*`;
  },
  validResult(data) {
    return data && Number.isInteger(data.sus_score) && data.sus_score >= 0 &&
      data.sus_score <= 100 && ["low", "review", "high", "critical"].includes(data.risk_level) &&
      Array.isArray(data.indicators) && data.indicators.every((item) => typeof item === "string") &&
      typeof data.message === "string";
  },
};
