// 分享域名白名单：抖音老域名 amemv.com要认，冒充域名要拒。运行：node --test test/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('../_worker.js', import.meta.url)), 'utf8');
const file = join(mkdtempSync(join(tmpdir(), 'dy-')), 'w.mjs');
writeFileSync(file, src);
const mod = (await import(file)).default;

function memKV() {
  const m = new Map();
  return { get: async (k) => (m.has(k) ? m.get(k) : null), put: async (k, v) => void m.set(k, String(v)), delete: async (k) => void m.delete(k), list: async () => ({ keys: [...m.keys()].map((name) => ({ name })), list_complete: true }) };
}
let calls = [];
globalThis.fetch = async (u) => {
  calls.push(String(u && u.url ? u.url : u));
  return new Response('upstream broken', { status: 500 });
};
let n = 0;
async function parse(text) {
  calls = [];
  const env = { TURNSTILE_DISABLED: '1', FEEDBACK_KV: memKV(), REDFOX_API_KEY: 'fake', ASSETS: { fetch: async () => new Response('asset') } };
  const ctx = { waitUntil() {}, passThroughOnException() {} };
  const req = new Request('https://douyinqushuiyin.pages.dev/api/parse?url=' + encodeURIComponent(text), { headers: { 'cf-connecting-ip': '198.51.100.' + (++n) } });
  const r = await mod.fetch(req, env, ctx);
  return { status: r.status, body: await r.text(), calls };
}
const REJECT = '只支持抖音链接';

for (const link of [
  'https://v.douyin.com/iRNBho6u/',
  'https://www.douyin.com/video/7300000000000000000',
  'https://www.iesdouyin.com/share/video/7300000000000000000/',
  'https://www.amemv.com/share/video/7300000000000000000/',
  'https://AMEMV.COM./share/video/7300000000000000000/',
]) {
  test('接受 ' + link, async () => {
    const r = await parse('复制打开抖音，看看【作品】 ' + link);
    assert.ok(!r.body.includes(REJECT), r.status + ' ' + r.body.slice(0, 160));
  });
}

for (const link of [
  'https://amemv.com.evil.example/x',
  'https://fakeamemv.com/x',
  'https://amemv.com-evil.com/x',
  'https://amemv.co/x',
  'https://v26-web.douyinvod.com/x.mp4',
  'https://evil.example/?u=https://www.amemv.com/x',
]) {
  test('拒绝冒充/非官方域名 ' + link, async () => {
    const r = await parse(link);
    assert.equal(r.status, 400, r.body.slice(0, 160));
    assert.ok(r.body.includes(REJECT), r.body.slice(0, 160));
    assert.equal(r.calls.length, 0, '不该调上游：' + r.calls.join(','));
  });
}
