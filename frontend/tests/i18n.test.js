import { describe, expect, it } from "vitest";

import messages from "../translations/messages";

describe("frontend translations", () => {
  it("exports both locales with required sections", () => {
    expect(Object.keys(messages)).toEqual(["en", "pt"]);
    for (const locale of ["en", "pt"]) {
      const entry = messages[locale];
      expect(entry.home).toBeDefined();
      expect(entry.nav).toBeDefined();
      expect(entry.sections).toBeDefined();
      expect(entry.lang).toBeDefined();
      expect(entry.nav.locations).toBeTruthy();
    }
  });

  it("each section uses human-readable labels", () => {
    const sections = ["locations", "items", "tags", "events", "audit"];
    sections.forEach((key) => {
      expect(messages.en.nav[key]).toMatch(/./);
      expect(messages.pt.nav[key]).toMatch(/./);
    });
  });

  it("language switcher options are present", () => {
    const langs = ["en", "pt"];
    for (const locale of langs) {
      expect(messages[locale].lang.en).toBe("English");
      expect(messages[locale].lang.pt).toBe("Português");
    }
  });
});
