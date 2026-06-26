/**
 * Take screenshots of key VulnGuard pages for README
 * Usage: node scripts/take-screenshots.mjs
 */
import { chromium } from "playwright";
import { mkdirSync } from "fs";
import { join } from "path";

const BASE = "http://localhost:3000";
const OUT = join(process.cwd(), "public", "screenshots");

mkdirSync(OUT, { recursive: true });

const pages = [
  { path: "/", name: "dashboard", width: 1440, height: 900 },
  { path: "/scan/new", name: "new-scan", width: 1440, height: 900 },
  { path: "/scan/history", name: "scan-history", width: 1440, height: 900 },
  { path: "/reports", name: "reports", width: 1440, height: 900 },
  { path: "/settings", name: "settings", width: 1440, height: 900 },
];

const browser = await chromium.launch({ headless: true });

for (const { path, name, width, height } of pages) {
  const ctx = await browser.newContext({ viewport: { width, height } });
  const page = await ctx.newPage();
  try {
    await page.goto(`${BASE}${path}`, { waitUntil: "networkidle", timeout: 20000 });
    await page.waitForTimeout(1000);
    await page.screenshot({ path: join(OUT, `${name}.png`), fullPage: true });
    console.log(`✓ ${name}.png`);
  } catch (e) {
    console.error(`✗ ${name}.png — ${e.message}`);
  }
  await ctx.close();
}

await browser.close();
console.log("\nDone — screenshots saved to public/screenshots/");
