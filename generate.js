const fs = require("fs");
const path = require("path");
const net = require("net");

// إجبار السكريبت يستعمل DNS ديال Google و Cloudflare باش ما يتعطلش
const nodeDns = require("dns");
nodeDns.setServers(["8.8.8.8", "1.1.1.1"]);
const dns = nodeDns.promises;

const SOURCE_FILE = "sub.txt";
const OUTPUT_DIR = "output";
const WORKERS = 80; // تقللنا من 80 لـ 25 باش ما يتبلوكاش DNS
const DNS_TIMEOUT = 3000; // 3 ثواني كافيين

const GOOGLE_URLS = [
  "https://www.gstatic.com/ipranges/goog.json",
  "https://www.gstatic.com/ipranges/cloud.json"
];

const DEFAULT_SOURCES = [
  "https://github.com/Mohamedhnini-a/testeur/raw/refs/heads/main/working_configs.txt",
  "https://github.com/Mohamedhnini-a/testeur-2/raw/refs/heads/main/working_configs.txt"
];

const DNS_CACHE = new Map();
const ASN_CACHE = new Map();
const ASN_NAME_CACHE = new Map();

// ============ لائحة الشركات المعروفة ============
const KNOWN_PROVIDERS = {
  // CDN / Edge
  13335: "Cloudflare", 209242: "Cloudflare", 400095: "Cloudflare", 14789: "Cloudflare", 395747: "Cloudflare",
  15169: "Google", 396982: "Google Cloud", 19527: "Google", 139070: "Google", 36384: "Google",
  16509: "AWS", 14618: "AWS", 8987: "AWS CloudFront", 24544: "AWS", 7203: "AWS",
  8075: "Microsoft Azure", 8068: "Microsoft Azure", 20940: "Akamai", 16625: "Akamai", 63949: "Akamai (Linode)", 33905: "Akamai",
  54113: "Fastly",
  // Clouds / VPS
  14061: "DigitalOcean", 393406: "DigitalOcean",
  20473: "Vultr",
  24940: "Hetzner", 213230: "Hetzner", 215859: "Hetzner",
  16276: "OVH",
  31898: "Oracle Cloud",
  12876: "Scaleway",
  51167: "Contabo", 141995: "Contabo", 40021: "Contabo",
  45102: "Alibaba Cloud", 37963: "Alibaba Cloud", 134963: "Alibaba Cloud",
  132203: "Tencent Cloud", 45090: "Tencent Cloud",
  136907: "Huawei Cloud",
  197540: "Netcup",
  199524: "Gcore", 59245: "Gcore", 205196: "Gcore",
  210644: "Aeza", 197695: "Aeza",
  9009: "M247",
  30058: "Hivelocity",
  60068: "Datacamp (CDN77)", 212238: "Datacamp", 
  59711: "DreamHost",
  62240: "Clouvider",
  3214: "Xtom"
};

// باش نعرفو نعطيو الأولوية فـ الترتيب
const KNOWN_ORDER = [
  "Cloudflare", "AWS", "AWS CloudFront", "Google", "Google Cloud", 
  "Fastly", "Microsoft Azure", "Akamai", "Akamai (Linode)", 
  "Hetzner", "OVH", "DigitalOcean", "Oracle Cloud", "Vultr", 
  "Scaleway", "Alibaba Cloud", "Tencent Cloud", "Huawei Cloud", "Contabo"
];

const NAME_KEYWORDS = [
  [/cloudflare/i, "Cloudflare"], [/google/i, "Google"], [/fastly/i, "Fastly"],
  [/akamai/i, "Akamai"], [/amazon|aws/i, "AWS"], [/microsoft|azure/i, "Microsoft Azure"],
  [/hetzner/i, "Hetzner"], [/digitalocean/i, "DigitalOcean"], [/vultr|choopa/i, "Vultr"],
  [/ovh/i, "OVH"], [/oracle/i, "Oracle Cloud"], [/scaleway|online sas/i, "Scaleway"],
  [/contabo/i, "Contabo"], [/linode/i, "Akamai (Linode)"], [/alibaba/i, "Alibaba Cloud"],
  [/tencent/i, "Tencent Cloud"], [/huawei/i, "Huawei Cloud"], [/gcore/i, "Gcore"]
];

// ============ Utilities ============
function log(message) {
  console.log(`[${new Date().toISOString().slice(11, 19)}] ${message}`);
}

function decodeBase64(value) {
  try {
    let s = value.replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
    s += "=".repeat((4 - s.length % 4) % 4);
    return Buffer.from(s, "base64").toString("utf8");
  } catch { return ""; }
}

function extractConfigs(text) {
  const result = new Set();
  const add = content => {
    const matches = content.match(/(?:vless|vmess|trojan):\/\/[^\s"'<>]+/gi) || [];
    for (const item of matches) result.add(item.trim().replace(/&amp;/g, "&"));
  };
  add(text);
  const decoded = decodeBase64(text);
  if (decoded && decoded !== text) add(decoded);
  return [...result];
}

function ipv4Number(ip) {
  return ip.split(".").reduce((n, part) => (n << 8n) | BigInt(part), 0n);
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
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8) throw new Error("Invalid IPv6");
  return groups.reduce((n, part) => (n << 16n) | BigInt("0x" + (part || "0")), 0n);
}

function ipv6ToReversedNibbles(ip) {
  let value = ip.toLowerCase();
  if (value.includes(".")) {
    const idx = value.lastIndexOf(":");
    const [a, b, c, d] = value.slice(idx + 1).split(".").map(Number);
    const hex4 = ((a << 8) | b).toString(16).padStart(4, "0") + ":" + ((c << 8) | d).toString(16).padStart(4, "0");
    value = value.slice(0, idx + 1) + hex4;
  }
  const parts = value.split("::");
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts.length > 1 ? (parts[1] ? parts[1].split(":") : []) : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) throw new Error("Invalid IPv6");
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  const hex = groups.map(g => g.padStart(4, "0")).join("");
  return hex.split("").reverse().join(".");
}

function isPrivateIP(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const p = ip.split(".").map(Number);
    return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
           (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] === 0;
  }
  if (v === 6) {
    const l = ip.toLowerCase();
    return l === "::1" || l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd") || l === "::";
  }
  return false;
}

// ============ Google Ranges ============
function parseRange(cidr) {
  const [network, prefixText] = cidr.split("/");
  const version = net.isIP(network);
  if (!version) return null;
  const width = version === 4 ? 32 : 128;
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > width) return null;
  const value = version === 4 ? ipv4Number(network) : ipv6Number(network);
  const shift = BigInt(width - prefix);
  return { version, shift, network: value >> shift };
}

function compileRanges(prefixes) {
  return prefixes.map(parseRange).filter(Boolean);
}

function matchIP(ip, ranges) {
  const version = net.isIP(ip);
  if (!version) return false;
  let value;
  try { value = version === 4 ? ipv4Number(ip) : ipv6Number(ip); } catch { return false; }
  return ranges.some(r => r.version === version && (value >> r.shift) === r.network);
}

async function loadGoogleRanges() {
  const frontend = [], cloud = [];
  for (let i = 0; i < GOOGLE_URLS.length; i++) {
    try {
      const r = await fetch(GOOGLE_URLS[i], { signal: AbortSignal.timeout(20000) });
      if (!r.ok) continue;
      const data = await r.json();
      const prefixes = data.prefixes.flatMap(p => [p.ipv4Prefix, p.ipv6Prefix].filter(Boolean));
      if (i === 0) frontend.push(...prefixes);
      else cloud.push(...prefixes);
    } catch (e) { log(`[GOOGLE RANGE FAIL] ${e.message}`); }
  }
  return { frontend: compileRanges(frontend), cloud: compileRanges(cloud) };
}

// ============ ASN Lookup (Team Cymru) ============
async function lookupASN(ip) {
  if (ASN_CACHE.has(ip)) return ASN_CACHE.get(ip);
  const promise = (async () => {
    try {
      const version = net.isIP(ip);
      let query;
      if (version === 4) query = ip.split(".").reverse().join(".") + ".origin.asn.cymru.com";
      else if (version === 6) query = ipv6ToReversedNibbles(ip) + ".origin.asn.cymru.com";
      else return null;

      const records = await dns.resolveTxt(query);
      if (!records || !records.length) return null;
      const txt = records[0].join("");
      const parts = txt.split("|").map(s => s.trim());
      if (parts.length < 2) return null;
      const asns = parts[0].split(/\s+/).filter(Boolean).map(n => parseInt(n, 10)).filter(n => !isNaN(n));
      return { asns, prefix: parts[1], country: parts[2], registry: parts[3] };
    } catch { return null; }
  })();
  ASN_CACHE.set(ip, promise);
  return promise;
}

async function lookupASNName(asn) {
  if (ASN_NAME_CACHE.has(asn)) return ASN_NAME_CACHE.get(asn);
  const promise = (async () => {
    try {
      const records = await dns.resolveTxt(`AS${asn}.asn.cymru.com`);
      if (!records || !records.length) return null;
      const txt = records[0].join("");
      const parts = txt.split("|").map(s => s.trim());
      return parts[4] || null;
    } catch { return null; }
  })();
  ASN_NAME_CACHE.set(asn, promise);
  return promise;
}

// تسمية المزود (تجميع الـ ASNs حسب سمية الشركة)
function classifyProvider(asn, asName) {
  if (KNOWN_PROVIDERS[asn]) return KNOWN_PROVIDERS[asn];
  if (asName) {
    for (const [re, name] of NAME_KEYWORDS) {
      if (re.test(asName)) return name;
    }
    // إلا مالقاش فـ اللائحة، كياخد السمية الحقيقية ديال الشركة من Team Cymru
    return asName.split(",")[0].trim(); 
  }
  return `AS${asn}`;
}

async function classifyIP(ip, googleRanges) {
  if (googleRanges) {
    if (matchIP(ip, googleRanges.frontend)) return { provider: "Google", asn: 15169, asName: "GOOGLE, US" };
    if (matchIP(ip, googleRanges.cloud)) return { provider: "Google Cloud", asn: 396982, asName: "GOOGLE-CLOUD-PLATFORM, US" };
  }
  if (isPrivateIP(ip)) return { provider: "Private IP", asn: null, asName: null };

  const info = await lookupASN(ip);
  if (!info || !info.asns.length) return { provider: "Unknown", asn: null, asName: null };

  const asn = info.asns[0];
  const asName = await lookupASNName(asn);
  return { provider: classifyProvider(asn, asName), asn, asName };
}

function providerSlug(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

// ============ Config Helpers ============
function getHost(config) {
  try {
    if (config.startsWith("vmess://")) {
      const json = JSON.parse(decodeBase64(config.slice(8)));
      return json.add || json.address || json.host || "";
    }
    const url = new URL(config);
    return url.hostname.replace(/^\[|\]$/g, "");
  } catch { return ""; }
}

async function resolveHost(host) {
  if (!host) return [];
  if (net.isIP(host)) return [host];
  if (DNS_CACHE.has(host)) return DNS_CACHE.get(host);

  const promise = dns.lookup(host, { all: true, verbatim: true })
    .then(records => [...new Set(records.map(r => r.address))])
    .catch(() => []);
  DNS_CACHE.set(host, promise);
  return promise;
}

async function fetchSources() {
  let sources = [...DEFAULT_SOURCES]; 

  if (fs.existsSync(SOURCE_FILE)) {
    const fileContent = fs.readFileSync(SOURCE_FILE, "utf8");
    const fileSources = fileContent.split(/\r?\n/).map(x => x.trim()).filter(x => x && !x.startsWith("#"));
    sources.push(...fileSources);
  }
  sources = [...new Set(sources)];

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
        const r = await fetch(source, { signal: AbortSignal.timeout(30000) });
        if (!r.ok) { log(`[SOURCE FAILED] ${r.status} ${source}`); continue; }
        const content = await r.text();
        collected.push(...extractConfigs(content));
        log(`[SOURCE OK] جاب ${content.length} حرف من ${source.split('/').pop()}`);
      } catch (e) {
        log(`[SOURCE ERROR] ${e.message}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(10, sources.length) }, worker));
  return [...new Set(collected)];
}

// ============ Main ============
async function main() {
  const start = Date.now();
  log("IP → PROVIDER CLASSIFIER STARTED");

  if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  log("Loading Google IP ranges...");
  const googleRanges = await loadGoogleRanges();
  
  log("Fetching configuration sources...");
  const configs = await fetchSources();
  log(`Total unique configs: ${configs.length}`);

  const providerConfigs = new Map();
  const providerMeta = new Map();
  const ipMap = new Map();

  let completed = 0, unresolved = 0, invalid = 0;
  let cursor = 0;

  async function processWorker() {
    while (true) {
      const index = cursor++;
      if (index >= configs.length) return;
      const config = configs[index];

      try {
        const host = getHost(config);
        if (!host) { invalid++; continue; }

        const ips = await resolveHost(host);
        if (!ips.length) { unresolved++; continue; }

        const configProviders = new Set();

        for (const ip of ips) {
          let info = ipMap.get(ip);
          if (!info) {
            info = await classifyIP(ip, googleRanges);
            ipMap.set(ip, info);
          }
          configProviders.add(info.provider);

          if (!providerMeta.has(info.provider)) {
            providerMeta.set(info.provider, { asns: new Set(), names: new Set(), ips: new Set() });
          }
          const meta = providerMeta.get(info.provider);
          if (info.asn) meta.asns.add(info.asn);
          if (info.asName) meta.names.add(info.asName);
          meta.ips.add(ip);
        }

        for (const provider of configProviders) {
          if (!providerConfigs.has(provider)) providerConfigs.set(provider, new Set());
          providerConfigs.get(provider).add(config);
        }
      } catch {
        invalid++;
      }

      completed++;
      if (completed % 200 === 0 || completed === configs.length) {
        log(`PROGRESS ${completed}/${configs.length} | PROVIDERS ${providerConfigs.size} | DNS ${DNS_CACHE.size} | ASN ${ASN_CACHE.size}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(WORKERS, configs.length) }, processWorker));

  // ===== Save outputs =====
  const providerSummary = [];
  let otherConfigs = new Set(); 

  // ترتيب المزودين: الأولوية للمعروفين ومن بعد بالعدد
  const sortedProviders = [...providerConfigs].sort((a, b) => {
    const aIdx = KNOWN_ORDER.indexOf(a[0]);
    const bIdx = KNOWN_ORDER.indexOf(b[0]);
    
    if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
    if (aIdx !== -1) return -1;
    if (bIdx !== -1) return 1;
    return b[1].size - a[1].size;
  });

  for (const [provider, set] of sortedProviders) {
    // إلا كان المزود عندو 20 ولا كثر، نسجلو فـ ملف بوحدو
    if (set.size >= 20) {
      const slug = providerSlug(provider) || "unknown";
      const file = path.join(OUTPUT_DIR, `${slug}.txt`);
      fs.writeFileSync(file, [...set].join("\n") + (set.size ? "\n" : ""));
      
      const meta = providerMeta.get(provider) || { asns: new Set(), names: new Set(), ips: new Set() };
      providerSummary.push({
        provider,
        slug,
        file,
        configs: set.size,
        ips: meta.ips.size,
        asns: [...meta.asns],
        names: [...meta.names]
      });
    } else {
      // إلا كانو قلال (أقل من 20)، نجمعوهم فـ ملف واحد باش ما نعمروش GitHub
      for (const config of set) otherConfigs.add(config);
    }
  }

  // حفظ الملفات الصغار المتبقيين
  if (otherConfigs.size > 0) {
    fs.writeFileSync(path.join(OUTPUT_DIR, "_other_providers.txt"), [...otherConfigs].join("\n") + "\n");
  }

  // حفظ خريطة الـ IPs
  const ipLines = [...ipMap.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([ip, info]) => {
      const tag = info.asn ? ` [AS${info.asn}${info.asName ? ` ${info.asName}` : ""}]` : "";
      return `${ip}\t${info.provider}${tag}`;
    });
  fs.writeFileSync(path.join(OUTPUT_DIR, "_ip_providers.tsv"), ipLines.join("\n") + "\n");

  // حفظ الـ JSON ديال الإحصائيات
  fs.writeFileSync(
    path.join(OUTPUT_DIR, "_providers.json"),
    JSON.stringify(providerSummary, null, 2) + "\n"
  );

  // حفظ ملف الإحصائيات النهائي
  const summaryLines = [
    "IP → PROVIDER CLASSIFICATION",
    "============================",
    `Total configs: ${configs.length}`,
    `Classified IPs: ${ipMap.size}`,
    `Providers found: ${providerConfigs.size}`,
    `Unresolved hosts: ${unresolved}`,
    `Invalid configs: ${invalid}`,
    `DNS cache: ${DNS_CACHE.size}`,
    `ASN cache: ${ASN_CACHE.size}`,
    `ASN name cache: ${ASN_NAME_CACHE.size}`,
    `Duration: ${((Date.now() - start) / 1000).toFixed(2)}s`,
    `Finished: ${new Date().toISOString()}`,
    "",
    "BREAKDOWN BY PROVIDER",
    "---------------------",
    ...providerSummary.map(p =>
      `${p.provider.padEnd(28)} configs=${String(p.configs).padStart(5)}  ips=${String(p.ips).padStart(5)}  ASN=${p.asns.join(",") || "-"}`
    )
  ];
  const summary = summaryLines.join("\n");
  fs.writeFileSync(path.join(OUTPUT_DIR, "_summary.txt"), summary + "\n");

  console.log("\n" + summary);
  log(`DONE — outputs in ./${OUTPUT_DIR}/`);
}

main().catch(e => {
  console.error("[FATAL]", e);
  process.exit(1);
});
