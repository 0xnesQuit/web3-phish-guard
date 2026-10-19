// Guard3 icons: crop the shield (the "G3" mark) out of brand/guard3-logo.png and rasterise it to the
// extension icon sizes, plus a logo.svg wrapper for store listings. Uses ffmpeg when it is available; when it is
// not (e.g. a CI box without ffmpeg) it leaves the committed public/icons/* in place, so the build still works.
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";

const LOGO = "brand/guard3-logo.png";
const OUT = "public/icons";
const SIZES = [16, 32, 48, 128, 256, 512];
// the shield occupies this box in the 1448x1086 logo (above the "Guard3" wordmark)
const CROP = "crop=760:760:344:40";

function findFfmpeg() {
  const candidates = [
    process.env.FFMPEG,
    "ffmpeg",
    `${process.env.LOCALAPPDATA ?? ""}/Microsoft/WinGet/Packages/Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe/ffmpeg-9.0.2-full_build/bin/ffmpeg.exe`,
  ].filter(Boolean);
  for (const c of candidates) {
    try { execFileSync(c, ["-version"], { stdio: "ignore" }); return c; } catch { /* try next */ }
  }
  return null;
}

const ff = findFfmpeg();
if (!ff || !existsSync(LOGO)) {
  console.log(`icons: ${ff ? "logo missing" : "ffmpeg not found"} — keeping committed public/icons/*`);
} else {
  const { mkdirSync, readFileSync, writeFileSync } = await import("node:fs");
  mkdirSync(OUT, { recursive: true });
  for (const s of SIZES) {
    execFileSync(ff, ["-hide_banner", "-loglevel", "error", "-y", "-i", LOGO, "-vf", `${CROP},scale=${s}:${s}:flags=lanczos`, `${OUT}/icon${s}.png`]);
  }
  const b64 = readFileSync(`${OUT}/icon512.png`).toString("base64");
  writeFileSync(`${OUT}/logo.svg`, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512"><image href="data:image/png;base64,${b64}" width="512" height="512"/></svg>`);
  console.log(`icons: regenerated from ${LOGO} (${SIZES.join("/")} + logo.svg)`);
}
