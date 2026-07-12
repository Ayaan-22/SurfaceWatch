import { describe, expect, it } from "vitest";

import { getAggressiveScanDisabledReason } from "./scan-authorization";

const NOW_MS = Date.parse("2026-07-09T12:00:00Z");

describe("aggressive scan disabled messaging", () => {
  it("explains expired authorization", () => {
    expect(
      getAggressiveScanDisabledReason(
        {
          authorization_expires_at: "2026-07-08T23:59:59Z",
          max_scan_profile: "aggressive"
        },
        NOW_MS
      )
    ).toBe("Aggressive scanning is disabled because authorization has expired.");
  });

  it("explains safe-only approval when authorization is still current", () => {
    expect(
      getAggressiveScanDisabledReason(
        {
          authorization_expires_at: "2026-07-10T23:59:59Z",
          max_scan_profile: "safe"
        },
        NOW_MS
      )
    ).toBe("Aggressive scanning is disabled because this scope is approved for safe-only scanning.");
  });

  it("does not return a disabled reason for aggressive approval with current authorization", () => {
    expect(
      getAggressiveScanDisabledReason(
        {
          authorization_expires_at: "2026-07-10T23:59:59Z",
          max_scan_profile: "aggressive"
        },
        NOW_MS
      )
    ).toBeNull();
  });
});
