import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";

const command = process.env.CONNECT_TEST_BROWSER;
if (!command)
  throw new Error(
    "Set CONNECT_TEST_BROWSER to an installed Chrome, Chromium or Edge executable.",
  );
const root = fileURLToPath(new URL("../", import.meta.url));
const profile = await mkdtemp(path.join(tmpdir(), "connect-browser-"));
let resolveReport;
const reported = new Promise((resolve) => {
  resolveReport = resolve;
});
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "POST" && req.url === "/report") {
      let data = "";
      for await (const part of req) {
        data += part;
        if (data.length > 65536) throw new Error("Oversized test report");
      }
      const result = JSON.parse(data);
      res.writeHead(200);
      res.end("ok");
      resolveReport(result);
      return;
    }
    let name = new URL(req.url, "http://localhost").pathname;
    if (name.startsWith("/node_modules/@noble/") && !path.extname(name))
      name += ".js";
    const file = path.resolve(root, "." + name);
    const mime = {
      ".html": "text/html",
      ".js": "text/javascript",
      ".json": "application/json",
    }[path.extname(file)];
    if (!file.startsWith(root) || !mime || req.method !== "GET") {
      res.writeHead(404);
      res.end();
      return;
    }
    const data = await readFile(file);
    res.writeHead(200, { "Content-Type": mime });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
const child = spawn(
  command,
  [
    "--headless",
    "--disable-gpu",
    "--disable-extensions",
    "--no-first-run",
    "--no-default-browser-check",
    "--remote-debugging-port=0",
    "--user-data-dir=" + profile,
    "http://127.0.0.1:" + port + "/test/browser.html",
  ],
  { windowsHide: true, stdio: "ignore" },
);
let timeout;
try {
  const result = await Promise.race([
    reported,
    new Promise((_, reject) => {
      timeout = setTimeout(
        () => reject(new Error("Browser conformance timed out after 60s")),
        60000,
      );
    }),
    new Promise((_, reject) => {
      child.once("error", reject);
      child.once("exit", (code) =>
        reject(new Error("Browser exited before reporting: " + code)),
      );
    }),
  ]);
  console.log(JSON.stringify(result));
  if (result.status !== "PASS") process.exitCode = 1;
} finally {
  clearTimeout(timeout);
  child.kill();
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  // The fresh browser profile contains only public conformance fixtures.
  if (
    path.dirname(path.resolve(profile)) !== path.resolve(tmpdir()) ||
    !path.basename(profile).startsWith("connect-browser-")
  )
    throw new Error("Unexpected temporary profile path");
  await rm(profile, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 200,
  }).catch(() => {});
}
