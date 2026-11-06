const fs = require('fs/promises');

// الليستة ديال الروابط ديالك
const sourceUrls = [
  "https://github.com/williamnecoo1-pixel/testrw/raw/refs/heads/main/reality_configs.txt",
];

// 🆕 الـ IP الجديد اللي غادي نبدلو بيه
const REPLACE_HOST = '216.239.38.126';

// 🆕 اللائحة ديال الأنواع المسموحة (زدت xhttp و splithttp)
const ALLOWED_NETWORKS = ['ws', 'xhttp', 'splithttp', 'grpc'];

const FETCH_TIMEOUT_MS = 30_000;
const CONCURRENCY_LIMIT = 30;

function timeoutSignal(ms) {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return AbortSignal.timeout(ms);
  }
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

function isPrintableText(text) {
  if (!text) return false;
  const cleaned = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  return cleaned.length / text.length > 0.9;
}

function decodeIfBase64(text) {
  try {
    const cleaned = text.trim().replace(/\s+/g, '');
    const normalized = cleaned.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const decoded = Buffer.from(padded, 'base64').toString('utf8');

    if (!isPrintableText(decoded)) return text;

    if (
      decoded.includes('vless://') ||
      decoded.includes('trojan://') ||
      decoded.includes('vmess://')
    ) {
      return decoded;
    }
  } catch (_) {}

  return text;
}

function b64DecodeUtf8(b64) {
  try {
    b64 = b64.trim().replace(/\s/g, '');
    b64 += '='.repeat((4 - (b64.length % 4)) % 4);
    return Buffer.from(b64, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function b64EncodeUtf8(str) {
  return Buffer.from(str, 'utf8').toString('base64');
}

async function fetchWithLimit(urls, limit) {
  const results = [];
  for (let i = 0; i < urls.length; i += limit) {
    const batch = urls.slice(i, i + limit);
    const batchResults = await Promise.allSettled(
      batch.map((url) =>
        fetch(url, {
          headers: { 'user-agent': 'Mozilla/5.0' },
          signal: timeoutSignal(FETCH_TIMEOUT_MS),
        })
          .then((res) => {
            if (!res.ok) {
              console.warn(`[FAIL ${res.status}] ${url}`);
              return '';
            }
            return res.text();
          })
          .catch((err) => {
            console.warn(`[ERR] ${url} — ${err?.message ?? String(err)}`);
            return '';
          })
      )
    );
    results.push(...batchResults);
  }
  return results;
}

async function main() {
  const results = await fetchWithLimit(sourceUrls, CONCURRENCY_LIMIT);

  const texts = results
    .filter((r) => r.status === 'fulfilled' && r.value)
    .map((r) => r.value);

  if (texts.length === 0) {
    console.error('⚠️ All sources failed to fetch.');
  }

  const filteredConfigs = [];

  // ============================================================
  // Sets ديال الفلترة (Dedupe)
  // ============================================================
  const seenVless = new Set();
  const seenVmess = new Set();
  const seenTrojan = new Set();

  for (const text of texts) {
    let decodedText = text;

    if (
      !text.includes('vless://') &&
      !text.includes('trojan://') &&
      !text.includes('vmess://')
    ) {
      decodedText = decodeIfBase64(text);
    }

    const lines = decodedText.split(/\r?\n/);

    for (let line of lines) {
      line = line.trim();
      if (!line) continue;

      // ==========================================
      // 1. VMess
      // ==========================================
      if (line.startsWith('vmess://')) {
        try {
          const cleanLine = line.split('#')[0];
          const b64 = cleanLine.slice(8).trim();
          const jsonStr = b64DecodeUtf8(b64);
          if (!jsonStr) continue;

          const config = JSON.parse(jsonStr);

          // 🆕 هنا رديناها كتشيك على اللائحة المسموحة (ws, xhttp...) عوض ws بوحدها
          const netType = String(config.net || '').toLowerCase();
          
          if (
            !ALLOWED_NETWORKS.includes(netType) ||
            String(config.tls || '').toLowerCase() !== 'tls' ||
            parseInt(config.port, 10) !== 443
          ) {
            continue;
          }

          // ✅ فلترة التكرار حسب الـ ID فقط
          const vmessId = String(config.id || '').toLowerCase().trim();
          if (!vmessId || seenVmess.has(vmessId)) continue;
          seenVmess.add(vmessId);

          const server = String(config.add || '').toLowerCase().trim();
          if (!server) continue;

          // 🆕 تبديل الـ host بـ 216.239.38.126
          config.add = REPLACE_HOST;

          filteredConfigs.push('vmess://' + b64EncodeUtf8(JSON.stringify(config)));
        } catch (_) {}
        continue;
      }

      // ==========================================
      // 2. VLESS / Trojan
      // ==========================================
      const cleanLine = line.split('#')[0].trim();
      if (
        !cleanLine.startsWith('vless://') &&
        !cleanLine.startsWith('trojan://')
      ) {
        continue;
      }

      try {
        const url = new URL(cleanLine);
        const protocol = url.protocol.replace(':', '').toLowerCase();
        const port = url.port === '' ? 443 : parseInt(url.port, 10);
        const netType = String(url.searchParams.get('type') || '').toLowerCase(); // 🆕

        // 🆕 هنا تا هوما رديناهم كتشيك على اللائحة المسموحة
        if (
          (protocol !== 'vless' && protocol !== 'trojan') ||
          !ALLOWED_NETWORKS.includes(netType) ||
          url.searchParams.get('security') !== 'tls' ||
          port !== 443
        ) {
          continue;
        }

        const username = url.username.toLowerCase().trim();
        if (!username) continue;

        // ✅ فلترة VLESS حسب الـ UUID فقط
        if (protocol === 'vless') {
          if (seenVless.has(username)) continue;
          seenVless.add(username);
        }

        // ✅ فلترة Trojan حسب الـ Password فقط
        if (protocol === 'trojan') {
          if (seenTrojan.has(username)) continue;
          seenTrojan.add(username);
        }

        // 🆕 تبديل الـ hostname بـ 216.239.38.126
        url.hostname = REPLACE_HOST;

        let finalConfig = url.toString();
        const originalRemark = line.split('#')[1];
        if (originalRemark) finalConfig += `#${originalRemark}`;

        filteredConfigs.push(finalConfig);
      } catch (_) {}
    }
  }

  if (filteredConfigs.length === 0) {
    console.error('⚠️ No configs found! All sources failed or filter too strict.');
    try {
      const old = await fs.readFile('sub.txt', 'utf8');
      if (old.trim().length > 0) {
        console.warn('ℹ️ Keeping existing sub.txt to avoid wiping the subscription.');
        return;
      }
    } catch (_) {}
    process.exit(1);
  }

  await fs.writeFile('sub.txt', filteredConfigs.join('\n'), 'utf8');
  console.log(`✅ Saved ${filteredConfigs.length} configs to sub.txt (host → ${REPLACE_HOST})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
