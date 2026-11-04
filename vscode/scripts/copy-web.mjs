// Copies the UI built for VS Code (web/dist-vscode) and the icon into media/.
import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const web = join(root, "..", "web", "dist-vscode");
if (!existsSync(join(web, "index.html"))) {
  console.error("web/dist-vscode is missing. Run `pnpm run build:vscode` in web/ first.");
  process.exit(1);
}
const media = join(root, "media");
rmSync(media, { recursive: true, force: true });
mkdirSync(media, { recursive: true });
cpSync(web, join(media, "web"), { recursive: true });
cpSync(join(root, "..", "assets", "icon.png"), join(media, "icon.png"));
