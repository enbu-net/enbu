import { describe, expect, it } from "vite-plus/test";
import { folderName } from "./paths";

describe("folderName", () => {
  it("keeps Japanese and spaces in a folder name", () => {
    expect(folderName("/Users/山田 太郎/開発 プロジェクト")).toBe("開発 プロジェクト");
    expect(folderName("C:\\Users\\山田 太郎\\マイ リポジトリ\\")).toBe("マイ リポジトリ");
  });

  it("keeps a name that ends in a space", () => {
    expect(folderName("/home/kota/repo ")).toBe("repo ");
  });

  it("keeps characters outside the Basic Multilingual Plane", () => {
    expect(folderName("/home/kota/🔑 secrets")).toBe("🔑 secrets");
  });
});
