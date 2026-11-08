const fs = require("fs");
const dns = require("dns").promises;
const net = require("net");

const SOURCE_FILE = "sub.txt";
const GOOGLE_RANGES_URL = "https://www.gstatic.com/ipranges/goog.json";

function decodeContent(text) {
  if (/vless:\/\//i.test(text)) return text;

  try {
    const decoded = Buffer.from(
      text.replace(/\s/g, ""),
      "base64"
    ).toString("utf8");

    if (/vless:\/\//i.test(decoded)) return decoded;
  } catch {}

  return text;
}

function extractConfigs(text) {
  return [...new Set(
    decodeContent(text).match(/vless:\/\/[^\s"'<>]+/gi) || []
  )];
}

function ipv4ToBigInt(ip) {
  return ip.split(".").reduce(
    (n, part) => (n << 8n) | BigInt(part), 0n
  );
}

function ipv6ToBigInt(ip) {
  let value = ip.toLowerCase();

  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const ipv4 = value.slice(lastColon + 1);
    const n = ipv4ToBigInt(ipv4);

    const first = Number((n >> 16n) & 0xffffn).toString(16);
    const second = Number(n & 0xffffn).toString(16);

    value = value.slice(0, lastColon) + ":" + first + ":" + second;
  }

  const halves = value.split("::");
  let left = halves[0] ? halves[0].split(":") : [];
  let right = halves[1] ? halves[1].split(":") : [];

  const missing = 8 - left.length - right.length;
  const groups = [...left, ...Array(missing).fill("0"), ...right];

  return groups.reduce(
    (n, part) => (n << 16n) | BigInt("0x" + (part || "0")),
    0n
  );
}

function inRange(ip, prefix) {
  const [network, bitsText] = prefix.split("/");
  const version = net.isIP(ip);

  if (!version || net.isIP(network) !== version) return false;

  const bits = Number(bitsText);
  const width = version === 4 ? 32 : 128;

  if (!Number.isInteger(bits) || bits < 0 || bits > width) {
    return false;
  }

  const address = version === 4
    ? ipv4ToBigInt(ip)
    : ipv6ToBigInt(ip);

  const base = version === 4
    ? ipv4ToBigInt(network)
    : ipv6ToBigInt(network);

  const shift = BigInt(width - bits);

  return (address >> shift) === (base >> shift);
}

function isGoogleIP(ip, ranges) {
  return ranges.some(prefix => inRange(ip, prefix));
}

async function getGoogleRanges() {
  const response = await fetch(GOOGLE_RANGES_URL);

  if (!response.ok) {
    throw new Error("Google IP ranges download failed: " + response.status);
  }

  const data = await response.json();

  return data.prefixes.flatMap(item => [
    item.ipv4Prefix,
    item.ipv6Prefix
  ].filter(Boolean));
}

async function resolveIPs(host) {
  if (net.isIP(host)) return [host];

  try {
    const records = await dns.lookup(host, { all: true });
    return [...new Set(records.map(record => record.address))];
  } catch {
    return [];
  }
}

async function getConfigs() {
  if (!fs.existsSync(SOURCE_FILE)) {
    throw new Error("sub.txt not found");
  }

  const sources = fs.readFileSync(SOURCE_FILE, "utf8")
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith("#"));

  const configs = [];

  for (const source of sources) {
    if (/^vless:\/\//i.test(source)) {
      configs.push(source);
      continue;
    }

    if (!/^https?:\/\//i.test(source)) continue;

    try {
      console.log("[FETCH] " + source);

      const response = await fetch(source, {
        signal: AbortSignal.timeout(30000)
      });

      if (!response.ok) {
        console.log("[SOURCE FAILED] HTTP " + response.status);
        continue;
      }

      const content = await response.text();
      configs.push(...extractConfigs(content));

    } catch (error) {
      console.log("[SOURCE FAILED] " + error.message);
    }
  }

  return [...new Set(configs)];
}

async function main() {
  console.log("================================");
  console.log("     GOOGLE IP CONFIG FILTER");
  console.log("================================");

  const ranges = await getGoogleRanges();
  console.log("[GOOGLE] Loaded ranges: " + ranges.length);

  const configs = await getConfigs();

  console.log("[TOTAL] Configs: " + configs.length);

  const results = [];
  const googleIPs = new Set();

  let invalid = 0;
  let unresolved = 0;

  for (let i = 0; i < configs.length; i++) {
    const config = configs[i];

    try {
      const url = new URL(config);
      const host = url.hostname.replace(/^\[|\]$/g, "");

      const ips = await resolveIPs(host);

      if (!ips.length) {
        unresolved++;
        continue;
      }

      const matched = ips.filter(ip => isGoogleIP(ip, ranges));

      if (matched.length) {
        results.push(config);
        matched.forEach(ip => googleIPs.add(ip));

        console.log(
          `[GOOGLE ${results.length}] ${host} -> ${matched.join(", ")}`
        );
      }

    } catch {
      invalid++;
    }

    if ((i + 1) % 500 === 0) {
      console.log(`[PROGRESS] ${i + 1}/${configs.length}`);
    }
  }

  fs.writeFileSync(
    "google_configs.txt",
    results.join("\n") + (results.length ? "\n" : "")
  );

  fs.writeFileSync(
    "google_ips.txt",
    [...googleIPs].sort().join("\n") +
      (googleIPs.size ? "\n" : "")
  );

  const stats = [
    "Google IP Config Collector",
    "===========================",
    `Total configs: ${configs.length}`,
    `Google matched: ${results.length}`,
    `Unique Google IPs: ${googleIPs.size}`,
    `Unresolved: ${unresolved}`,
    `Invalid configs: ${invalid}`,
    `Google IP ranges: ${ranges.length}`,
    `Finished: ${new Date().toISOString()}`
  ].join("\n");

  fs.writeFileSync("filter_stats.txt", stats + "\n");

  console.log("\n" + stats);
}

main().catch(error => {
  console.error("[FATAL]", error);
  process.exit(1);
});
 
