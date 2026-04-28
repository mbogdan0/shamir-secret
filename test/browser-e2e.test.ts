import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { chromium } from "playwright";

const execFileAsync = promisify(execFile);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifactPath = resolve(projectRoot, "dist/index.html");

test(
  "file artifact generates and recovers locally without network requests",
  { timeout: 60000 },
  async () => {
    await execFileAsync("node", ["--experimental-strip-types", "scripts/build.ts"], {
      cwd: projectRoot
    });

    const browser = await chromium.launch();
    const networkRequests = new Set<string>();

    try {
      const page = await browser.newPage();
      page.on("request", (request) => {
        const url = request.url();
        if (/^(?:https?|wss?):/i.test(url)) {
          networkRequests.add(url);
        }
      });

      await page.goto(pathToFileURL(artifactPath).href);
      await page.getByText("Use for real secrets?").waitFor();
      assert.equal(
        await page.getByText("formal third-party cryptographic audit").isVisible(),
        true
      );
      assert.equal(await page.getByText("high-value secrets").isVisible(), true);
      assert.equal(await page.locator("#secretModeHint").isVisible(), true);
      assert.match(
        (await page.locator("#secretModeHint").textContent()) ?? "",
        /Text mode uses an app-specific envelope/
      );

      const secret = "browser e2e local recovery";
      await page.locator("#secretHexInput").fill(secret);
      await page.locator("#shareCount").fill("3");
      await page.locator("#threshold").fill("2");
      await page.getByRole("button", { name: "Generate shares" }).click();

      const shareTexts = page.locator("#shareList .share-text");
      await shareTexts.first().waitFor();
      const shares = await shareTexts.allTextContents();
      assert.equal(shares.length, 3);
      assert.equal(await page.getByText("Single group 2-of-3").isVisible(), true);

      await page.getByRole("tab", { name: "Recover" }).click();
      await page.locator("#sharesInput").fill(shares.slice(0, 2).join("\n"));
      await page.getByRole("button", { name: "Recover secret" }).click();

      await page.locator("#recoveredTextBlock").waitFor();
      assert.equal(await page.locator("#recoveredText").inputValue(), secret);
      assert.match(
        (await page.locator("#message").textContent()) ?? "",
        /Text mode uses an app-specific envelope/
      );
      assert.deepEqual([...networkRequests], []);
    } finally {
      await browser.close();
    }
  }
);
