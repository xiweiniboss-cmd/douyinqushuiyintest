// 抖音无水印解析下载站（Cloudflare Pages 单文件 Worker）
// 根目录放 _worker.js：/api/* 走这里，其余走 env.ASSETS 静态资源
// 解析通道：RedFoxHub /story/api/parseWork/videoDownload/douyin
// 需要环境变量 REDFOX_API_KEY（与小红书站同一个 key，直接复用）
// 鉴权：请求头 REDFOX_API_KEY；成功码 code=2000

const REDFOX_BASE = 'https://redfox.hk';
const UA_MOBILE =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
const UA_PC =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
    },
  });
}

function getClientIp(request, env) {
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf.trim();
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return '';
}

// ---------- RedFoxHub ----------
async function redfoxPost(path, apiKey, body) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 25000);
  try {
    const resp = await fetch(REDFOX_BASE + path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        REDFOX_API_KEY: apiKey,
        'User-Agent': UA_PC,
        Accept: 'application/json',
      },
      body: JSON.stringify({ ...body, source: 'douyin-dl-pages' }),
      signal: ctrl.signal,
    });
    const text = await resp.text();
    let j = null;
    try {
      j = JSON.parse(text);
    } catch {
      throw new Error('RedFoxHub 返回了非 JSON 数据（HTTP ' + resp.status + '）');
    }
    if (resp.status === 401)
      throw new Error('RedFoxHub API Key 无效，请检查环境变量 REDFOX_API_KEY 是否正确');
    if (resp.status === 429) throw new Error('请求太频繁，请稍后重试');
    const code = j.code;
    const msg = String(j.msg || j.message || '');
    if (code && code !== 2000) {
      if (code === 401 || code === 4001) throw new Error('RedFoxHub 鉴权失败：' + msg);
      if (/余额|balance|insufficient|欠费/i.test(msg))
        throw new Error('RedFoxHub 余额不足，请前往 redfox.hk 控制台充值后再试');
      throw new Error('RedFoxHub：' + (msg || 'code=' + code));
    }
    if (!resp.ok) throw new Error('RedFoxHub 请求失败（HTTP ' + resp.status + '）' + (msg ? '：' + msg : ''));
    return j.data !== undefined ? j.data : j;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- 链接处理 ----------
function extractDouyinUrl(text) {
  if (!text) return null;
  const m = String(text).match(/https?:\/\/[^\s"'<>]+/i);
  return m ? m[0].replace(/[.,;!?\]]+$/, '') : null;
}

async function resolveShortLink(url) {
  // 手动跟跳转，拿到最终 URL（不下载页面 body）
  let cur = url;
  for (let i = 0; i < 5; i++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 12000);
    try {
      const resp = await fetch(cur, {
        method: 'GET',
        redirect: 'manual',
        headers: { 'User-Agent': UA_MOBILE },
        signal: ctrl.signal,
      });
      const loc = resp.headers.get('location');
      await resp.arrayBuffer().catch(() => {});
      if (resp.status >= 300 && resp.status < 400 && loc) {
        cur = new URL(loc, cur).toString();
        continue;
      }
      return cur;
    } catch {
      return cur;
    } finally {
      clearTimeout(timer);
    }
  }
  return cur;
}

function canonicalDouyinUrl(finalUrl) {
  // https://www.douyin.com/video/{id} 或 /note/{id}（图文）
  const m = String(finalUrl).match(/douyin\.com\/(video|note)\/(\d+)/i);
  if (m) return 'https://www.douyin.com/' + m[1].toLowerCase() + '/' + m[2];
  return null;
}

// ---------- 结果提取 ----------
function ensureHttps(u) {
  if (typeof u !== 'string') return u;
  if (u.startsWith('//')) return 'https:' + u;
  return u;
}
function isVideoUrl(u) {
  return typeof u === 'string' && (/\.mp4(\?|$)/i.test(u) || /douyinvod|video/i.test(u));
}
function pickUrl(item) {
  if (typeof item === 'string') return item;
  if (!item || typeof item !== 'object') return null;
  return (
    item.downloadUrl ||
    item.download_url ||
    item.url ||
    item.playUrl ||
    item.play_url ||
    item.src ||
    null
  );
}
function extractMedia(data) {
  const videos = [];
  const images = [];
  const seen = new Set();
  const pushV = (u) => {
    const h = ensureHttps(pickUrl(u) || u);
    if (typeof h === 'string' && /^https?:\/\//i.test(h) && !seen.has(h)) {
      seen.add(h);
      videos.push(h);
    }
  };
  const pushI = (u) => {
    const h = ensureHttps(pickUrl(u) || u);
    if (typeof h === 'string' && /^https?:\/\//i.test(h) && !seen.has(h)) {
      seen.add(h);
      images.push(h);
    }
  };
  const resources = data.resources || data.resource || data.medias || [];
  if (Array.isArray(resources)) {
    for (const r of resources) {
      const t = String(r.type || '').toLowerCase();
      if (t === 'video' || (!t && isVideoUrl(pickUrl(r)))) pushV(r);
      else if (t === 'image' || t === 'pic' || t === 'photo') pushI(r);
      else if (pickUrl(r)) {
        // 类型不明：按 URL 特征分流
        if (isVideoUrl(pickUrl(r))) pushV(r);
        else pushI(r);
      }
    }
  }
  // 顶层直链兜底
  for (const k of ['videoUrl', 'video_url', 'downloadUrl', 'download_url', 'playUrl', 'play_url', 'url'])
    if (data[k]) pushV(data[k]);
  for (const k of ['cover', 'coverUrl', 'cover_url'])
    if (data[k] && !images.includes(ensureHttps(data[k]))) {
      /* cover 单独返回，不混入 images */
    }
  return { videos, images };
}

async function parseShareViaRedFox(shareText, apiKey, debug) {
  const rawUrl = extractDouyinUrl(shareText);
  if (!rawUrl) throw new Error('没找到有效的链接，请粘贴抖音分享链接');
  if (!/douyin\.com/i.test(rawUrl)) throw new Error('这不是抖音链接，请检查后重试');

  const finalUrl = await resolveShortLink(rawUrl);
  const canonical = canonicalDouyinUrl(finalUrl);
  const routes = [];
  if (canonical) routes.push({ name: 'canonical', url: canonical });
  if (finalUrl && finalUrl !== canonical) routes.push({ name: 'final', url: finalUrl });
  routes.push({ name: 'raw', url: rawUrl });

  const dbg = debug ? { routes: [] } : null;
  let lastErr = null;
  for (const r of routes) {
    try {
      const data = await redfoxPost('/story/api/parseWork/videoDownload/douyin', apiKey, { url: r.url });
      const { videos, images } = extractMedia(data || {});
      const title = data.desc || data.title || data.aweme_desc || '';
      const cover = ensureHttps(data.cover || data.coverUrl || data.cover_url || '');
      if (dbg) dbg.routes.push({ name: r.name, keys: data ? Object.keys(data) : [], videos: videos.length, images: images.length });
      if (videos.length || images.length) {
        return {
          title: String(title).slice(0, 200),
          cover,
          videos,
          images,
          type: videos.length && !images.length ? 'video' : images.length && !videos.length ? 'image' : 'mix',
          ...(debug ? { debug: dbg } : {}),
        };
      }
      lastErr = new Error('解析到了内容，但没找到可下载的视频/图片地址');
      if (dbg) dbg.routes[dbg.routes.length - 1].empty = true;
    } catch (e) {
      lastErr = e;
      if (dbg) dbg.routes.push({ name: r.name, error: String(e.message || e).slice(0, 120) });
    }
  }
  const err = new Error(lastErr ? lastErr.message : '解析失败，请稍后重试');
  if (debug) err.debug = dbg;
  throw err;
}

// ---------- 主入口 ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/parse') {
      const shareText = url.searchParams.get('url') || '';
      const debug = url.searchParams.get('debug') === '1';
      const apiKey = (env.REDFOX_API_KEY || '').trim();
      if (!shareText.trim()) return json({ ok: false, error: '请先粘贴抖音分享链接' }, 400);
      if (!apiKey)
        return json(
          {
            ok: false,
            error:
              '未配置 RedFoxHub API Key：请去 redfox.hk 注册并在控制台「API密钥」创建一个 key（可与小红书站复用同一个），然后在 Cloudflare Pages → Settings → Environment variables 添加 REDFOX_API_KEY（重新部署后生效）',
          },
          500
        );
      try {
        const result = await parseShareViaRedFox(shareText, apiKey, debug);
        return json({ ok: true, ...result });
      } catch (e) {
        const body = { ok: false, error: e.message || '解析失败' };
        if (debug && e.debug) body.debug = e.debug;
        return json(body, 502);
      }
    }

    if (url.pathname === '/api/diag') {
      // 轻量自检：不暴露 key
      return json({
        ok: true,
        hasApiKey: !!(env.REDFOX_API_KEY || '').trim(),
        hasAssets: typeof env.ASSETS?.fetch === 'function',
      });
    }

    // 静态资源
    if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
      try {
        return await env.ASSETS.fetch(request);
      } catch {}
    }
    return new Response('Not Found', { status: 404 });
  },
};
