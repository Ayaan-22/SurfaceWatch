import { describe, expect, it } from "vitest";

import { apiDateMs } from "./api";

describe("api date parsing", () => {
  it("treats timezone-less API timestamps as UTC", () => {
    expect(apiDateMs("2026-07-03T10:09:38")).toBe(Date.parse("2026-07-03T10:09:38Z"));
  });

  it("preserves timestamps that already include a timezone", () => {
    expect(apiDateMs("2026-07-03T10:09:38+05:00")).toBe(Date.parse("2026-07-03T10:09:38+05:00"));
  });
});
