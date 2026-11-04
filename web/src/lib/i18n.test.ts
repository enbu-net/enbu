import { afterEach, describe, expect, it } from "vite-plus/test";
import { m } from "../paraglide/messages";
import { getLocale, localStorageKey, setLocale } from "../paraglide/runtime";

afterEach(() => {
  localStorage.removeItem(localStorageKey);
});

describe("messages", () => {
  it("prefers the saved locale over the browser's", () => {
    localStorage.setItem(localStorageKey, "ja");
    expect(getLocale()).toBe("ja");
  });

  it("falls back to English for an unsupported locale", () => {
    localStorage.setItem(localStorageKey, "fr");
    expect(getLocale()).toBe("en");
  });

  it("interpolates parameters in both locales", () => {
    expect(m.repo_current({ owner: "octo", repo: "hello" }, { locale: "en" })).toBe(
      "Repository: octo/hello",
    );
    expect(m.auth_expiresIn({ seconds: 30 }, { locale: "ja" })).toBe("有効期限まで 30 秒");
    expect(m.dashboard_duplicateKey({ key: "MY_SECRET" }, { locale: "ja" })).toBe(
      "キー「MY_SECRET」はすでに存在します。既存のシークレットを編集してください。",
    );
  });

  it("follows the current locale", async () => {
    await setLocale("ja", { reload: false });
    expect(m.sidebar_navigation()).toBe("ナビゲーション");
    await setLocale("en", { reload: false });
    expect(m.sidebar_navigation()).toBe("Navigation");
  });
});
