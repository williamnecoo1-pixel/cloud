const fs = require("fs");
const dns = require("dns").promises;
const net = require("net");

const SOURCE_FILE = "sub.txt";
const WORKERS = 80;
const DNS_TIMEOUT = 8000;

const GOOGLE_URLS = [
  "https://www.gstatic.com/ipranges/goog.json",
  "https://www.gstatic.com/ipranges/cloud.json"
];

const DNS_CACHE = new Map();

function log(message) {
  console.log(`[${new Date().toISOString().slice(11, 19)}] ${message}`);
}

function decodeBase64(value) {
  try {
    let s = value.replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
    s += "=".repeat((4 - s.length % 4) % 4);
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return "";
  }
}

function extractConfigs(text) {
  const result = new Set();

  const add = content => {
    const matches = content.match(
      /(?:vless|vmess|trojan):\/\/[^\s"'<>]+/gi
    ) || [];

    for (const item of matches) {
      result.add(item.trim().replace(/&amp;/g, "&"));
    }
  };

  add(text);

  const decoded = decodeBase64(text);

  if (decoded && decoded !== text) {
    add(decoded);
  }

  return [...result];
}

function ipv4Number(ip) {
  return ip.split(".").reduce(
    (n, part) => (n << 8n) | BigInt(part),
    0n
  );
}

function ipv6Number(ip) {
  let value = ip.toLowerCase();

  if (value.includes(".")) {
    const index = value.lastIndexOf(":");
    const n = ipv4Number(value.slice(index + 1));

    const a = ((n >> 16n) & 65535n).toString(16);
    const b = (n & 65535n).toString(16);

    value = value.slice(0, index) + ":" + a + ":" + b;
  }

  const parts = value.split("::");

  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts[1] ? parts[1].split(":") : [];

  const missing = 8 - left.length - right.length;

  if (missing < 0) throw new Error("Invalid IPv6");

  const groups = [
    ...left,
    ...Array(missing).fill("0"),
    ...right
  ];

  if (groups.length !== 8) throw new Error("Invalid IPv6");

  return groups.reduce(
    (n, part) => (n << 16n) | BigInt("0x" + (part || "0")),
    0n
  );
}

function parseRange(cidr) {
  const [network, prefixText] = cidr.split("/");
  const version = net.isIP(network);

  if (!version) return null;

  const width = version === 4 ? 32 : 128;
  const prefix = Number(prefixText);

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > width) {
    return null;
  }

  const value = version === 4
    ? ipv4Number(network)
    : ipv6Number(network);

  const shift = BigInt(width - prefix);

  return {
    version,
    shift,
    network: value >> shift
  };
}

function compileRanges(prefixes) {
  return prefixes
    .map(parseRange)
    .filter(Boolean);
}

function matchIP(ip, ranges) {
  const version = net.isIP(ip);

  if (!version) return false;

  let value;

  try {
    value = version === 4
      ? ipv4Number(ip)
      : ipv6Number(ip);
  } catch {
    return false;
  }

  return ranges.some(range =>
    range.version === version &&
    (value >> range.shift) === range.network
  );
}

async function loadGoogleRanges() {
  const all = [];
  const frontend = [];
  const cloud = [];

  for (let i = 0; i < GOOGLE_URLS.length; i++) {
    const response = await fetch(GOOGLE_URLS[i], {
      signal: AbortSignal.timeout(20000)
    });

    if (!response.ok) {
      throw new Error(`Google ranges HTTP ${response.status}`);
    }

    const data = await response.json();

    const prefixes = data.prefixes.flatMap(item => [
      item.ipv4Prefix,
      item.ipv6Prefix
    ].filter(Boolean));

    if (i === 0) frontend.push(...prefixes);
    else cloud.push(...prefixes);

    all.push(...prefixes);
  }

  return {
    all: compileRanges(all),
    frontend: compileRanges(frontend),
    cloud: compileRanges(cloud)
  };
}

function getHost(config) {
  try {
    if (config.startsWith("vmess://")) {
      const json = JSON.parse(
        decodeBase64(config.slice(8))
      );

      return json.add || json.address || json.host || "";
    }

    const url = new URL(config);

    return url.hostname.replace(/^\[|\]$/g, "");
  } catch {
    return "";
  }
}

async function resolveHost(host) {
  if (!host) return [];

  if (net.isIP(host)) return [host];

  if (DNS_CACHE.has(host)) {
    return DNS_CACHE.get(host);
  }

  const promise = dns.lookup(host, {
    all: true,
    verbatim: true
  }).then(records => [
    ...new Set(records.map(record => record.address))
  ]).catch(() => []);

  DNS_CACHE.set(host, promise);

  return promise;
}

async function fetchSources() {
  if (!fs.existsSync(SOURCE_FILE)) {
    throw new Error("sub.txt not found");
  }

  const sources = fs.readFileSync(SOURCE_FILE, "utf8")
    .split(/\r?\n/)
    .map(x => x.trim())
    .filter(x => x && !x.startsWith("#"));

  const collected = [];

  let index = 0;

  async function worker() {
    while (index < sources.length) {
      const source = sources[index++];

      if (/^(vless|vmess|trojan):\/\//i.test(source)) {
        collected.push(source);
        continue;
      }

      if (!/^https?:\/\//i.test(source)) continue;

      try {
        const response = await fetch(source, {
          signal: AbortSignal.timeout(30000)
        });

        if (!response.ok) {
          log(`[SOURCE FAILED] ${response.status} ${source}`);
          continue;
        }

        const content = await response.text();
        collected.push(...extractConfigs(content));

      } catch (error) {
        log(`[SOURCE ERROR] ${error.message}`);
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(10, sources.length) }, worker)
  );

  return [...new Set(collected)];
}

async function main() {
  const start = Date.now();

  log("GOOGLE ECOSYSTEM COLLECTOR STARTED");

  log("Loading Google IP ranges...");

  const ranges = await loadGoogleRanges();

  log(`Google Frontend ranges: ${ranges.frontend.length}`);
  log(`Google Cloud ranges: ${ranges.cloud.length}`);

  log("Fetching configuration sources...");

  const configs = await fetchSources();

  log(`Total unique configs: ${configs.length}`);

  const frontendResults = new Set();
  const cloudResults = new Set();
  const allResults = new Set();

  const googleIPs = new Set();
  const cloudIPs = new Set();

  let completed = 0;
  let unresolved = 0;
  let invalid = 0;

  let cursor = 0;

  async function processWorker() {
    while (true) {
      const index = cursor++;

      if (index >= configs.length) return;

      const config = configs[index];

      try {
        const host = getHost(config);

        if (!host) {
          invalid++;
          continue;
        }

        const ips = await resolveHost(host);

        if (!ips.length) {
          unresolved++;
          continue;
        }

        let frontendMatch = false;
        let cloudMatch = false;

        for (const ip of ips) {
          if (matchIP(ip, ranges.frontend)) {
            frontendMatch = true;
            googleIPs.add(ip);
          }

          if (matchIP(ip, ranges.cloud)) {
            cloudMatch = true;
            cloudIPs.add(ip);
          }
        }

        if (frontendMatch || cloudMatch) {
          allResults.add(config);

          if (frontendMatch) frontendResults.add(config);
          if (cloudMatch) cloudResults.add(config);
        }

      } catch {
        invalid++;
      }

      completed++;

      if (completed % 500 === 0 || completed === configs.length) {
        log(
          `PROGRESS ${completed}/${configs.length} | ` +
          `MATCHED ${allResults.size} | ` +
          `DNS CACHE ${DNS_CACHE.size}`
        );
      }
    }
  }

  await Promise.all(
    Array.from(
      { length: Math.min(WORKERS, configs.length) },
      processWorker
    )
  );

  function save(file, set) {
    fs.writeFileSync(
      file,
      [...set].join("\n") + (set.size ? "\n" : "")
    );
  }

  save("google_configs.txt", allResults);
  save("google_frontend.txt", frontendResults);
  save("google_cloud.txt", cloudResults);
  save("google_ips.txt", googleIPs);
  save("google_cloud_ips.txt", cloudIPs);

  const stats = [
    "GOOGLE ECOSYSTEM COLLECTOR",
    "==========================",
    `Total configs: ${configs.length}`,
    `Google ecosystem: ${allResults.size}`,
    `Google Frontend: ${frontendResults.size}`,
    `Google Cloud: ${cloudResults.size}`,
    `Unique Frontend IPs: ${googleIPs.size}`,
    `Unique Cloud IPs: ${cloudIPs.size}`,
    `Unresolved: ${unresolved}`,
    `Invalid: ${invalid}`,
    `DNS cache: ${DNS_CACHE.size}`,
    `Workers: ${WORKERS}`,
    `Duration: ${((Date.now() - start) / 1000).toFixed(2)} seconds`,
    `Finished: ${new Date().toISOString()}`
  ].join("\n");

  fs.writeFileSync("filter_stats.txt", stats + "\n");

  console.log("\n" + stats);
  log("COLLECTION COMPLETED");
}

main().catch(error => {
  console.error("[FATAL]", error);
  process.exit(1);
});
