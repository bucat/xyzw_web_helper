/**
 * 访问密码门（Access Gate）
 *
 * 环境变量（Cloudflare Pages → Settings → Environment variables，Production 与 Preview 都要配）：
 *   ACCESS_PASSWORD  必填，访问密码
 *   ACCESS_SECRET    必填，32 位以上随机串，用于给登录 Cookie 签名（换掉即踢掉所有会话）
 *   ACCESS_DAYS      可选，登录有效期天数，默认 7
 *
 * 未配置时返回 503 并提示如何配置（fail-closed，不放行任何内容）。
 */

const COOKIE_NAME = 'xyzw_gate';

const enc = new TextEncoder();

const toHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function sha256(str) {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(str)));
}

async function hmacHex(key, msg) {
  const k = await crypto.subtle.importKey(
    'raw',
    enc.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return toHex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}

function getCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

/** Cookie 格式： exp|hmac(secret, "v1|"+exp) */
async function makeToken(secret, days) {
  const exp = String(Date.now() + days * 86400 * 1000);
  return exp + '|' + (await hmacHex(secret, 'v1|' + exp));
}

async function verifyToken(secret, token) {
  if (!token) return false;
  const [exp, sig] = token.split('|');
  if (!exp || !sig) return false;
  if (!Number(exp) || Number(exp) < Date.now()) return false;
  const want = await hmacHex(secret, 'v1|' + exp);
  if (want.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** 只允许站内相对路径，防止开放重定向 */
function safeNext(next) {
  if (!next || typeof next !== 'string') return '/';
  if (!next.startsWith('/') || next.startsWith('//')) return '/';
  return next;
}

const loginPage = (next, msg = '') => `<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>需要验证 · XYZW</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:linear-gradient(135deg,#667eea,#764ba2);font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
  .card{background:#fff;padding:36px 32px;border-radius:14px;width:min(92vw,360px);box-shadow:0 18px 50px rgba(0,0,0,.22)}
  h1{font-size:19px;color:#222;margin-bottom:6px}
  p.sub{font-size:13px;color:#888;margin-bottom:22px}
  input{width:100%;padding:12px 14px;border:1px solid #ddd;border-radius:8px;font-size:15px;outline:none}
  input:focus{border-color:#667eea}
  button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:8px;cursor:pointer;
         background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;font-size:15px}
  .err{margin-top:12px;color:#d03050;font-size:13px;min-height:18px}
</style></head>
<body>
  <form class="card" method="POST" action="/__gate">
    <h1>XYZW 游戏管理系统</h1>
    <p class="sub">请输入访问密码</p>
    <input type="password" name="password" placeholder="密码" autocomplete="current-password" autofocus required>
    <input type="hidden" name="next" value="${next.replace(/"/g, '&quot;')}">
    <button type="submit">进入</button>
    <div class="err">${msg}</div>
  </form>
</body></html>`;

const setupPage = (reason) => new Response(
  `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>站点未配置访问密码</title>
<style>body{font-family:-apple-system,"PingFang SC",sans-serif;max-width:640px;margin:12vh auto;padding:0 20px;color:#333;line-height:1.7}
code{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px}</style></head><body>
<h2>站点未配置访问密码，已拒绝访问</h2>
<p>请在 Cloudflare Pages 项目 → <b>Settings → Environment variables</b> 中添加：</p>
<ul>
  <li><code>ACCESS_PASSWORD</code>：访问密码</li>
  <li><code>ACCESS_SECRET</code>：32 位以上随机字符串</li>
</ul>
<p>保存后重新部署（环境变量变更需要触发一次新的部署才生效）。</p>
<p style="color:#999;font-size:13px">${reason}</p>
</body></html>`,
  { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } },
);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const PASSWORD = env.ACCESS_PASSWORD;
    const SECRET = env.ACCESS_SECRET || '';
    const DAYS = Number(env.ACCESS_DAYS || 7) || 7;

    // ---------- 密码门（在最前面，代理与静态资源一并保护）----------
    if (!PASSWORD) return setupPage('missing ACCESS_PASSWORD');
    if (!SECRET) return setupPage('missing ACCESS_SECRET');

    if (!(await verifyToken(SECRET, getCookie(request, COOKIE_NAME)))) {
      // 提交密码
      if (request.method === 'POST' && url.pathname === '/__gate') {
        let input = '';
        let next = '/';
        try {
          const form = await request.formData();
          input = String(form.get('password') || '');
          next = safeNext(String(form.get('next') || '/'));
        } catch {
          return new Response(loginPage('/', '请求格式不正确'), {
            status: 400,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
          });
        }
        if (!safeEqual(await sha256(input), await sha256(PASSWORD))) {
          return new Response(loginPage(next, '密码不正确'), {
            status: 401,
            headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
          });
        }
        const token = await makeToken(SECRET, DAYS);
        return new Response(null, {
          status: 302,
          headers: {
            Location: next,
            'Set-Cookie': `${COOKIE_NAME}=${token}; Path=/; Max-Age=${DAYS * 86400}; HttpOnly; Secure; SameSite=Lax`,
          },
        });
      }

      // 未登录：一切请求（含 /assets/*、/api/*、游戏 iframe）都只给登录页
      return new Response(loginPage(safeNext(url.pathname + url.search)), {
        status: 401,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }
    // ---------- 密码门结束，以下为原逻辑 ----------

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers":
        "Content-Type, Authorization, X-Requested-With",
    };

    // Handle OPTIONS request
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Proxy configuration
    const proxies = [
      {
        prefix: "/api/hortor-ucenter",
        target: "https://comb-platform.hortorgames.com",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Linux; Android 12; ALN-AL80 Build/HUAWEIALN-AL80; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.5735.196 Mobile Safari/537.36",
          Accept: "application/json",
          Host: "ucenter-app-server.hortorgames.com",
          "Content-Type": "application/json; charset=utf-8",
        },
      },
      {
        prefix: "/api/weixin-long",
        target: "https://long.open.weixin.qq.com",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Linux; Android 7.0; Mi-4c Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043632 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/WIFI Language/zh_CN",
          Accept: "*/*",
          Referer: "https://open.weixin.qq.com/",
        },
      },
      {
        prefix: "/api/weixin",
        target: "https://open.weixin.qq.com",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Linux; Android 7.0; Mi-4c Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043632 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/WIFI Language/zh_CN",
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          Referer: "https://open.weixin.qq.com/",
        },
      },
      {
        prefix: "/api/hortor",
        target: "https://comb-platform.hortorgames.com",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Linux; Android 12; 23117RK66C Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36",
          Accept: "*/*",
          Host: "comb-platform.hortorgames.com",
          Connection: "keep-alive",
          "Content-Type": "text/plain; charset=utf-8",
          Origin: "https://open.weixin.qq.com",
          Referer: "https://open.weixin.qq.com/",
        },
      },
    ].sort((a, b) => b.prefix.length - a.prefix.length); // Sort by length descending to match longest prefix first

    // Find matching proxy
    const proxy = proxies.find((p) => url.pathname.startsWith(p.prefix));

    if (proxy) {
      // Construct new URL
      const targetUrl = new URL(proxy.target);
      targetUrl.pathname = url.pathname.replace(proxy.prefix, "") || "/";
      targetUrl.search = url.search;

      // Prepare request headers
      const newHeaders = new Headers(request.headers);

      // Override headers based on proxy config
      Object.entries(proxy.headers).forEach(([key, value]) => {
        newHeaders.set(key, value);
      });

      // Special handling for Host header (Cloudflare might override it, but good to set intention)
      if (proxy.headers.Host) {
        newHeaders.set("Host", proxy.headers.Host);
      }

      // Create new request
      const newRequest = new Request(targetUrl.toString(), {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "follow",
      });

      try {
        const response = await fetch(newRequest);

        // Re-create response to add CORS headers
        const newResponse = new Response(response.body, response);
        Object.entries(corsHeaders).forEach(([key, value]) => {
          newResponse.headers.set(key, value);
        });

        return newResponse;
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // Serve static assets (Cloudflare Pages)
    // If env.ASSETS is available (e.g. in Cloudflare Pages Functions), use it to fetch static assets
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    // Default response for non-proxy paths
    return new Response("Not Found", { status: 404, headers: corsHeaders });
  },
};
