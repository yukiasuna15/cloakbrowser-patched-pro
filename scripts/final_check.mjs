import { launch } from "/home/agentuser/.npm-global/lib/node_modules/cloakbrowser/dist/index.js";

const out = [];
for (let i = 0; i < 2; i++) {
  const t0 = Date.now();
  try {
    const b = await launch({ headless: true });
    const p = await b.newPage();
    await p.goto("https://example.com", { timeout: 30000 });
    const title = await p.title();
    const ua = await p.evaluate(() => navigator.userAgent);
    await b.close();
    out.push({ i: i + 1, ok: true, title, ua, ms: Date.now() - t0 });
  } catch (e) {
    out.push({ i: i + 1, ok: false, err: String(e).slice(0, 150), ms: Date.now() - t0 });
  }
}
console.log(JSON.stringify(out, null, 2));
