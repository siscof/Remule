// SPDX-License-Identifier: GPL-2.0-or-later
//
// aMule's web UI against remuled (webui-on-remuled.sh), in Chromium: sign
// in, open every section and check it shows what remuled has, search the
// scripted server and download the result, add an ed2k link, and pause and
// resume it. A JavaScript error or a failed API call fails the run, except
// the two the UI expects: the session probe before signing in (401), and
// the chat sessions remuled does not serve yet (503, which amuleapi answers
// for a daemon without them and the Messages section shows as such).
//
// Environment: URL (amuleapi's root), PASS (the admin password), SHOTS
// (where screenshots go).

const { chromium } = require("playwright");

const URL = process.env.URL;
const PASS = process.env.PASS;
const SHOTS = process.env.SHOTS || ".";
const LINK_HASH = "0123456789ABCDEF0123456789ABCDEF";
const LINK = `ed2k://|file|webui%20link.iso|123456789|${LINK_HASH}|/`;

const problems = [];
const problem = (what) => {
  problems.push(what);
  console.log("  PROBLEM " + what);
};
const expected = (method, url, status) =>
  (status === 401 && url.endsWith("/auth/session")) ||
  (status === 503 && method === "GET" && url.endsWith("/api/v1/chats"));

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  page.on("pageerror", (e) => problem("page error: " + e.message));
  page.on("console", (m) => {
    // Failed requests are judged by the response handler below.
    if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) {
      problem("console error: " + m.text());
    }
  });
  page.on("response", (r) => {
    const u = r.url();
    const method = r.request().method();
    if (u.includes("/api/") && r.status() >= 400 && !expected(method, u, r.status())) {
      problem(`HTTP ${r.status()} ${method} ${u}`);
    }
  });

  const section = async (route) => {
    await page.goto(URL + "#/" + route);
    await page.waitForTimeout(1500);
  };
  // Wait until the page shows `text` (at most `secs`), or note it.
  const shows = async (what, text, secs = 15) => {
    try {
      await page.getByText(text).first().waitFor({ timeout: secs * 1000 });
      console.log(`  ok: ${what}`);
    } catch {
      problem(`${what}: no "${text}"`);
      await page.screenshot({ path: `${SHOTS}/missing-${problems.length}.png` });
    }
  };

  await page.goto(URL);
  await page.fill("#login-password", PASS);
  await page.click("button[type=submit]");
  await page.waitForSelector("a[data-route]", { timeout: 15000 });
  console.log("  ok: signed in");

  await section("networks");
  await shows("Networks lists the server", "remule interop server");
  await shows("Networks shows the eD2k connection", /ED2K: remule interop server · HighID/);
  await page.screenshot({ path: `${SHOTS}/networks.png` });

  await section("shared");
  await shows("Shared files lists the shared file", "webui shared file.bin");
  await page.screenshot({ path: `${SHOTS}/shared.png` });

  // A search on the server, its result downloaded.
  await section("search");
  await page.fill("input[name=query]", "interop");
  await page.click("form.search-form button[type=submit]");
  await shows("Search finds the server's file", "remule interop result.iso", 30);
  await page.screenshot({ path: `${SHOTS}/search.png` });
  const row = page.locator("tr", { hasText: "remule interop result.iso" }).first();
  await row.getByRole("button", { name: /download/i }).first().click();
  await page.waitForTimeout(1500);

  // An ed2k link added from the toolbar.
  const linkInput = page.locator("input[name=ed2k_link]:visible").first();
  await linkInput.fill(LINK);
  await linkInput.press("Enter");
  await page.waitForTimeout(1500);

  await section("downloads");
  await shows("Downloads lists the search result", "remule interop result.iso");
  await shows("Downloads lists the added link", "webui link.iso");
  await page.screenshot({ path: `${SHOTS}/downloads.png` });

  // Paused and resumed from its row.
  const linkRow = page.locator("tr", { hasText: "webui link.iso" }).first();
  await linkRow.locator("button[title=Pause]").click();
  try {
    await linkRow.getByText("Paused").waitFor({ timeout: 15000 });
    console.log("  ok: the link's download pauses");
  } catch {
    problem("the link's download does not show Paused");
  }
  await linkRow.locator("button[title=Resume]").click();
  try {
    await linkRow.getByText("Paused").waitFor({ state: "detached", timeout: 15000 });
    console.log("  ok: and resumes");
  } catch {
    problem("the link's download stays Paused");
  }

  for (const r of ["clients", "messages", "stats", "preferences", "about"]) {
    await section(r);
    await page.screenshot({ path: `${SHOTS}/${r}.png` });
  }
  await section("stats");
  await shows("Statistics shows the tree", "Uptime");
  await section("about");
  await shows("About names the daemon", "remuled");
  await section("preferences");
  await page.getByText("General", { exact: true }).first().click();
  await page.waitForTimeout(1000);
  const nick = await page
    .locator("input")
    .evaluateAll((els) => els.some((e) => e.value === "remuled-webui"));
  if (nick) console.log("  ok: Preferences shows the nick");
  else problem("Preferences shows the nick: no input holds remuled-webui");
  await page.screenshot({ path: `${SHOTS}/preferences-general.png` });

  await browser.close();
  if (problems.length) {
    console.log(`${problems.length} problem(s)`);
    process.exit(1);
  }
  console.log("  ok: no JavaScript errors or failed API calls");
})().catch((e) => {
  console.log("ERROR " + e.stack);
  process.exit(1);
});
