// Triggers Fighting · لوحة التحكم الخاصة (أدمن · حماية · ستريمرز · تحكم المالك)
// ملف واحد يشتغل على Bun. اللعبة هي اللي تتصل بالموقع (كل سيرفر كل 6 ثواني)، والموقع ما يتصل بروبلوكس أبداً.
// المتغيرات: TF_GAME_KEY (السر المشترك مع اللعبة) · DATABASE_URL (اختياري: Postgres للحفظ الدائم) · PORT
import { sql as pg } from "bun";

const GAME_KEY = Bun.env.TF_GAME_KEY ?? "";
const PORT = Number(Bun.env.PORT ?? 3000);
const HAS_DB = !!Bun.env.DATABASE_URL;
const LOCAL_FILE = Bun.env.TF_DATA_FILE ?? "./tf-data.json";

// ---------------------------------------------------------------- التخزين (بالذاكرة + حفظ دوري)
type Session = { token: string; userId: number; name: string; rank: number; streamer: boolean; exp: number };
type Cmd = { id: number; target: string; line: string; by: string; rank: number; created: number; done: string[]; results: { job: string; result: string; t: number }[] };
type Store = {
  servers: Record<string, { snap: any; seen: number }>;
  events: { id: number; job: string; k: string; t: number; d: any }[];
  cases: Record<string, any>;
  commands: Cmd[];
  logins: Record<string, { userId: number; name: string; display?: string; rank: number; streamer: boolean; exp: number }>;
  sessions: Record<string, Session>;
  appeals: { id: number; caseId: number; username: string; message: string; status: string; created: number; by?: string; note?: string }[];
  state: Record<string, any>;
  seq: number;
};
const db: Store = { servers: {}, events: [], cases: {}, commands: [], logins: {}, sessions: {}, appeals: [], state: {}, seq: 1 };
let dirty = false;
// الاستضافة المجانية تنام وتنمسح ذاكرتها: الأشياء المهمة (الاستئنافات) تنحفظ داخل اللعبة (DataStore) وترجع منها
let appealsDirty = false;
let needRestore = true;
const now = () => Math.floor(Date.now() / 1000);

async function load() {
  try {
    if (HAS_DB) {
      await pg`CREATE TABLE IF NOT EXISTS tf_store (k text PRIMARY KEY, v jsonb NOT NULL, updated timestamptz DEFAULT now())`;
      const rows = await pg`SELECT k, v FROM tf_store`;
      for (const r of rows) (db as any)[r.k] = r.v;
    } else {
      const f = Bun.file(LOCAL_FILE);
      if (await f.exists()) Object.assign(db, await f.json());
    }
  } catch (e) { console.error("load", e); }
  db.servers ??= {}; db.events ??= []; db.cases ??= {}; db.commands ??= []; db.logins ??= {}; db.sessions ??= {}; db.appeals ??= []; db.state ??= {}; db.seq ??= 1;
}
async function save() {
  if (!dirty) return;
  dirty = false;
  try {
    if (HAS_DB) {
      for (const k of ["events", "cases", "commands", "sessions", "appeals", "state", "seq", "logins"] as const) {
        const v = JSON.stringify((db as any)[k]);
        await pg`INSERT INTO tf_store (k, v, updated) VALUES (${k}, ${v}::jsonb, now()) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated = now()`;
      }
    } else {
      await Bun.write(LOCAL_FILE, JSON.stringify(db));
    }
  } catch (e) { console.error("save", e); dirty = true; }
}
setInterval(save, 10_000);
const nextId = () => { db.seq += 1; return db.seq; };

function prune() {
  const t = now();
  if (db.events.length > 6000) db.events.splice(0, db.events.length - 6000);
  db.commands = db.commands.filter((c) => t - c.created < 3 * 86400).slice(-500);
  for (const [k, v] of Object.entries(db.logins)) if (v.exp < t) delete db.logins[k];
  for (const [k, v] of Object.entries(db.sessions)) if (v.exp < t) delete db.sessions[k];
  for (const [k, v] of Object.entries(db.servers)) if (t - v.seen > 300) delete db.servers[k];
  const caseIds = Object.keys(db.cases);
  if (caseIds.length > 3000) for (const id of caseIds.sort((a, b) => db.cases[a].t - db.cases[b].t).slice(0, caseIds.length - 3000)) delete db.cases[id];
  if (db.appeals.length > 2000) db.appeals.splice(0, db.appeals.length - 2000);
}
setInterval(prune, 60_000);

// ---------------------------------------------------------------- أدوات
function safeEq(a: string, b: string) {
  if (!a || !b || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const json = (data: any, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const SEC_HEADERS = {
  "x-frame-options": "DENY", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
  "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
};
const hits: Record<string, number[]> = {};
function limited(key: string, max: number, windowSec: number) {
  const t = Date.now() / 1000;
  const list = (hits[key] ??= []).filter((x) => t - x < windowSec);
  hits[key] = list;
  if (list.length >= max) return true;
  list.push(t);
  return false;
}
function ipOf(req: Request, server: any) {
  return req.headers.get("x-forwarded-for")?.split(",")[0].trim() || server.requestIP(req)?.address || "?";
}
function cookie(req: Request, name: string) {
  const m = (req.headers.get("cookie") ?? "").match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
function sessionOf(req: Request): Session | null {
  const tok = cookie(req, "tfs");
  const s = tok ? db.sessions[tok] : null;
  if (!s || s.exp < now()) return null;
  return s;
}
const RANK_AR: Record<number, string> = { 0: "ستريمر", 1: "مساعد", 2: "مشرف", 3: "آدمن", 4: "مدير", 5: "مالك" };

function latestSnaps() {
  const t = now();
  return Object.entries(db.servers).filter(([, s]) => t - s.seen < 60).map(([job, s]) => ({ job, seen: s.seen, ...s.snap }));
}

// ---------------------------------------------------------------- اللعبة → الموقع
async function gameSync(req: Request) {
  if (!GAME_KEY || !safeEq(req.headers.get("x-tf-key") ?? "", GAME_KEY)) return json({ error: "forbidden" }, 403);
  const len = Number(req.headers.get("content-length") ?? 0);
  if (len > 4_000_000) return json({ error: "too large" }, 413);
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const snap = body?.snap ?? {};
  const job = String(snap.job ?? "unknown").slice(0, 64);
  const prev = db.servers[job]?.snap ?? {};
  // الأشياء الثقيلة تجي كل 10 دورات: نحتفظ بآخر نسخة
  for (const k of ["detectors", "streamers", "perkOff", "packs", "wave", "shield"]) if (snap[k] === undefined && prev[k] !== undefined) snap[k] = prev[k];
  db.servers[job] = { snap, seen: now() };
  for (const k of ["detectors", "streamers", "perkOff", "packs", "wave", "shield"]) if (snap[k] !== undefined) db.state[k] = snap[k];
  db.state.ac = snap.ac;
  db.state.commandsCount = snap.commands;

  for (const e of Array.isArray(body.events) ? body.events.slice(0, 500) : []) {
    if (!e || typeof e.k !== "string") continue;
    if (e.k === "login" && e.d?.code) {
      db.logins[String(e.d.code)] = { userId: Number(e.d.userId), name: String(e.d.name), display: e.d.display, rank: Number(e.d.rank) || 0, streamer: !!e.d.streamer, exp: Math.min(Number(e.d.exp) || now() + 600, now() + 600) };
      continue;
    }
    if (e.k === "case" && e.d?.id) {
      db.cases[String(e.d.id)] = { ...(db.cases[String(e.d.id)] ?? {}), ...e.d };
    }
    if (e.k === "restore" && e.d) {
      if (Array.isArray(e.d.appeals) && db.appeals.length === 0) db.appeals = e.d.appeals;
      for (const a of db.appeals) db.seq = Math.max(db.seq, Number(a.id) || 0);
      db.seq += 1000;
      needRestore = false;
      continue;
    }
    if (e.k === "caseindex" && Array.isArray(e.d)) {
      for (const c of e.d) if (c?.id && !db.cases[String(c.id)]) db.cases[String(c.id)] = { ...c, partial: true };
      continue;
    }
    db.events.push({ id: nextId(), job, k: e.k, t: Number(e.t) || now(), d: e.d });
  }
  for (const r of Array.isArray(body.results) ? body.results : []) {
    const c = db.commands.find((x) => x.id === Number(r.id));
    if (c) c.results.push({ job, result: String(r.result ?? "").slice(0, 1000), t: now() });
  }
  // الأوامر اللي لهالسيرفر
  const t = now();
  const out = [];
  for (const c of db.commands) {
    if (c.done.includes(job) || t - c.created > 120) continue;
    if (c.target !== "all" && c.target !== job) continue;
    if (c.target === "any" ) continue;
    c.done.push(job);
    out.push({ id: c.id, line: c.line, by: c.by, rank: c.rank });
  }
  // "any" = أي سيرفر واحد (مثل جلب قضية)
  for (const c of db.commands) {
    if (c.target === "any" && c.done.length === 0 && t - c.created <= 120) { c.done.push(job); out.push({ id: c.id, line: c.line, by: c.by, rank: c.rank }); }
  }
  dirty = true;
  const resp: any = { commands: out };
  if (needRestore) resp.restore = true;
  if (appealsDirty) { resp.persist = { appeals: db.appeals.slice(-300) }; appealsDirty = false; }
  return json(resp);
}

// ---------------------------------------------------------------- API الموقع
function need(s: Session | null, minRank: number) {
  if (!s) return json({ error: "login" }, 401);
  if (s.rank < minRank) return json({ error: "rank" }, 403);
  return null;
}
function queue(s: Session, line: string, target = "all") {
  const c: Cmd = { id: nextId(), target, line: line.slice(0, 400), by: s.name, rank: s.rank, created: now(), done: [], results: [] };
  db.commands.push(c);
  db.events.push({ id: nextId(), job: "web", k: "webcmd", t: now(), d: { by: s.name, rank: s.rank, line: c.line, target } });
  dirty = true;
  return c;
}

async function api(req: Request, url: URL, server: any): Promise<Response> {
  const p = url.pathname;
  const ip = ipOf(req, server);
  // POST لازم يجي من صفحتنا (حماية CSRF مع SameSite=Strict)
  if (req.method === "POST" && req.headers.get("x-tf") !== "1") return json({ error: "csrf" }, 403);

  if (p === "/api/login" && req.method === "POST") {
    if (limited("login:" + ip, 8, 300)) return json({ error: "انتظر شوي، محاولات كثيرة" }, 429);
    const { code } = await req.json().catch(() => ({}));
    const key = String(code ?? "").trim().toUpperCase();
    const l = db.logins[key];
    if (!l || l.exp < now()) return json({ error: "الكود غلط أو انتهى. اكتب ;weblogin باللعبة وخذ كود جديد" }, 400);
    delete db.logins[key];
    const token = crypto.randomUUID() + crypto.randomUUID();
    db.sessions[token] = { token, userId: l.userId, name: l.name, rank: l.rank, streamer: l.streamer, exp: now() + 12 * 3600 };
    db.events.push({ id: nextId(), job: "web", k: "weblogin", t: now(), d: { name: l.name, rank: l.rank, ip: ip.replace(/\.\d+$/, ".x") } });
    dirty = true;
    return json({ ok: true }, 200, { "set-cookie": `tfs=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${12 * 3600}` });
  }
  if (p === "/api/logout" && req.method === "POST") {
    const tok = cookie(req, "tfs");
    if (tok) delete db.sessions[tok];
    dirty = true;
    return json({ ok: true }, 200, { "set-cookie": "tfs=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  if (p === "/api/appeal" && req.method === "POST") {
    if (limited("appeal:" + ip, 3, 3600)) return json({ error: "قدمت استئنافات كثيرة، جرّب بعد ساعة" }, 429);
    const b = await req.json().catch(() => ({}));
    const caseId = Number(b.caseId);
    const username = String(b.username ?? "").trim().slice(0, 40);
    const message = String(b.message ?? "").trim().slice(0, 1500);
    if (!caseId || !username || message.length < 10) return json({ error: "عبّ رقم القضية واسمك ورسالة واضحة" }, 400);
    if (db.appeals.some((a) => a.caseId === caseId && a.status === "open")) return json({ error: "فيه استئناف مفتوح لهالقضية" }, 400);
    db.appeals.push({ id: nextId(), caseId, username, message, status: "open", created: now() });
    dirty = true; appealsDirty = true;
    return json({ ok: true });
  }

  const s = sessionOf(req);
  if (p === "/api/me") return s ? json({ name: s.name, rank: s.rank, rankAr: RANK_AR[s.rank], streamer: s.streamer, userId: s.userId }) : json({ error: "login" }, 401);
  if (!s) return json({ error: "login" }, 401);

  if (p === "/api/overview") {
    const snaps = latestSnaps();
    const players = snaps.reduce((n, x) => n + (x.players?.length ?? 0), 0);
    const t = now();
    const recent = db.events.filter((e) => t - e.t < 3600);
    const count = (k: string) => recent.filter((e) => e.k === k).length;
    return json({
      servers: snaps.map((x) => ({ job: x.job, players: x.players?.length ?? 0, uptime: x.uptime, version: x.version, studio: x.studio, seen: x.seen })),
      players, commands: db.state.commandsCount ?? 0, ac: db.state.ac ?? null, wave: db.state.wave ?? null,
      hour: { signals: count("signal"), cases: count("case"), reports: count("report"), kicks: count("kick"), evidence: count("evidence"), autoshadow: count("autoshadow") },
      openCases: Object.values(db.cases).filter((c: any) => ["open", "review", "jailed", "queued"].includes(c.status)).length,
      openAppeals: db.appeals.filter((a) => a.status === "open").length,
    });
  }
  if (p === "/api/players") {
    const r = need(s, 1); if (r) return r;
    const out: any[] = [];
    for (const x of latestSnaps()) for (const pl of x.players ?? []) out.push({ ...pl, job: x.job });
    return json(out);
  }
  if (p === "/api/events") {
    const r = need(s, 1); if (r) return r;
    const kinds = (url.searchParams.get("k") ?? "").split(",").filter(Boolean);
    const user = Number(url.searchParams.get("user") ?? 0);
    let list = db.events;
    if (kinds.length) list = list.filter((e) => kinds.includes(e.k));
    if (user) list = list.filter((e) => e.d?.userId === user || e.d?.killer?.id === user || e.d?.targetId === user);
    if (s.rank < 3) list = list.filter((e) => e.k !== "weblogin");
    return json(list.slice(-300).reverse());
  }
  if (p === "/api/detectors") {
    const r = need(s, 1); if (r) return r;
    return json({ detectors: db.state.detectors ?? {}, ac: db.state.ac ?? null, shield: db.state.shield ?? null });
  }
  if (p === "/api/cases") {
    const r = need(s, 2); if (r) return r;
    const list = Object.values(db.cases).map((c: any) => ({ id: c.id, userId: c.userId, name: c.name, reason: c.reason, status: c.status, score: c.score, t: c.t, partial: !!c.partial || !c.frames }));
    return json(list.sort((a: any, b: any) => b.t - a.t).slice(0, 400));
  }
  const cm = p.match(/^\/api\/case\/(\d+)$/);
  if (cm) {
    const r = need(s, 2); if (r) return r;
    const c = db.cases[cm[1]];
    if (!c || c.partial || !c.frames) queue(s, "!case " + cm[1], "any");
    return json(c ?? { id: Number(cm[1]), loading: true });
  }
  if (p === "/api/cases/refresh" && req.method === "POST") { const r = need(s, 2); if (r) return r; queue(s, "!cases", "any"); return json({ ok: true }); }
  if (p === "/api/decide" && req.method === "POST") {
    const r = need(s, 3); if (r) return r;
    const b = await req.json().catch(() => ({}));
    const what = String(b.what);
    if (!["clear", "jail", "wave", "unban"].includes(what)) return json({ error: "bad" }, 400);
    if (what === "unban" && s.rank < 4) return json({ error: "rank" }, 403);
    const c = queue(s, `!decide ${Number(b.caseId)} ${what} ${String(b.note ?? "").replace(/\s+/g, " ").slice(0, 200)}`, "any");
    return json({ ok: true, id: c.id });
  }
  if (p === "/api/run" && req.method === "POST") {
    const r = need(s, 1); if (r) return r;
    const b = await req.json().catch(() => ({}));
    let line = String(b.line ?? "").trim();
    if (!line) return json({ error: "empty" }, 400);
    if (line.startsWith("!")) return json({ error: "bad" }, 400);
    if (!line.startsWith(";")) line = ";" + line;
    const target = typeof b.target === "string" && /^[\w-]{1,64}$/.test(b.target) ? b.target : "all";
    const c = queue(s, line, target);
    return json({ ok: true, id: c.id });
  }
  const rm = p.match(/^\/api\/result\/(\d+)$/);
  if (rm) {
    const c = db.commands.find((x) => x.id === Number(rm[1]));
    if (!c || (c.by !== s.name && s.rank < 4)) return json({ error: "nf" }, 404);
    return json({ id: c.id, line: c.line, results: c.results, done: c.done.length });
  }
  if (p === "/api/commands") {
    const r = need(s, 1); if (r) return r;
    return json(db.state.commandList ?? null);
  }
  if (p === "/api/streamers") {
    if (s.rank < 1 && !s.streamer) return json({ error: "rank" }, 403);
    const recs = db.state.streamers ?? {};
    const activity = db.events.filter((e) => e.k === "streamer" && (s.rank >= 2 || e.d?.userId === s.userId)).slice(-300).reverse();
    if (s.rank < 2) {
      const mine = recs[String(s.userId)];
      return json({ streamers: mine ? { [String(s.userId)]: mine } : {}, perkOff: db.state.perkOff ?? {}, activity });
    }
    return json({ streamers: recs, perkOff: db.state.perkOff ?? {}, activity });
  }
  if (p === "/api/appeals") {
    const r = need(s, 3); if (r) return r;
    return json(db.appeals.slice().reverse());
  }
  if (p === "/api/appeal/decide" && req.method === "POST") {
    const r = need(s, 3); if (r) return r;
    const b = await req.json().catch(() => ({}));
    const a = db.appeals.find((x) => x.id === Number(b.id));
    if (!a) return json({ error: "nf" }, 404);
    const accept = b.accept === true;
    if (accept && s.rank < 4) return json({ error: "قبول الاستئناف (فك البان) للمدير والمالك" }, 403);
    a.status = accept ? "accepted" : "rejected"; a.by = s.name; a.note = String(b.note ?? "").slice(0, 300);
    if (accept) queue(s, `!decide ${a.caseId} unban ${a.note}`, "any");
    dirty = true; appealsDirty = true;
    return json({ ok: true });
  }
  if (p === "/api/sessions") {
    const r = need(s, 5); if (r) return r;
    return json(Object.values(db.sessions).map((x) => ({ name: x.name, rank: x.rank, exp: x.exp, me: x.token === s.token })));
  }
  if (p === "/api/sessions/revoke" && req.method === "POST") {
    const r = need(s, 5); if (r) return r;
    for (const [k, v] of Object.entries(db.sessions)) if (v.token !== s.token) delete db.sessions[k];
    dirty = true;
    return json({ ok: true });
  }
  return json({ error: "nf" }, 404);
}

// ---------------------------------------------------------------- الواجهة
const PAGE = /* html */ `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Triggers Fighting · لوحة التحكم</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#0B0D12;--s1:#121620;--s2:#1A1F2B;--s3:#272E3D;--t1:#F2F5F3;--t2:#AEB6B1;--t3:#6B7A71;--acc:#3DDC6B;--accd:#06210F;--red:#FF4D5E;--gold:#F5C542;--blue:#4DA3FF}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t1);font-family:Tajawal,system-ui,sans-serif;font-size:15px}
a{color:var(--acc)}button,input,select,textarea{font:inherit}
.top{display:flex;align-items:center;gap:16px;padding:14px 22px;background:var(--s1);border-bottom:1px solid var(--s3);position:sticky;top:0;z-index:5}
.logo{font-weight:900;font-size:20px;letter-spacing:.5px}.logo b{color:var(--acc)}
.who{margin-inline-start:auto;color:var(--t2);font-size:14px}
nav{display:flex;gap:4px;flex-wrap:wrap;padding:10px 22px;background:var(--s1);border-bottom:1px solid var(--s3)}
nav button{background:transparent;border:1px solid transparent;color:var(--t2);padding:8px 14px;border-radius:4px;cursor:pointer;font-weight:700;transform:skewX(-8deg)}
nav button span{display:inline-block;transform:skewX(8deg)}
nav button.on{background:var(--acc);color:var(--accd)}nav button:hover:not(.on){border-color:var(--s3);color:var(--t1)}
main{padding:22px;max-width:1400px;margin:0 auto}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(210px,1fr))}
.card{background:var(--s1);border:1px solid var(--s3);border-radius:6px;padding:16px}
.stat .n{font-size:34px;font-weight:900}.stat .l{color:var(--t2);font-weight:700}
h2{font-size:20px;margin:24px 0 10px;font-weight:900}h2:first-child{margin-top:0}
table{width:100%;border-collapse:collapse;background:var(--s1);border:1px solid var(--s3);border-radius:6px;overflow:hidden}
th,td{padding:9px 12px;text-align:right;border-bottom:1px solid var(--s2);vertical-align:top}th{background:var(--s2);color:var(--t2);font-size:13px;font-weight:800}
tr:hover td{background:#141925}
.pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:800;background:var(--s3);color:var(--t1)}
.on-p{background:var(--acc);color:var(--accd)}.sh-p{background:#2a3550;color:#bcd2ff}.off-p{background:#3a2228;color:#ffb3bb}.ca-p{background:#3b3416;color:var(--gold)}
.btn{background:var(--s2);border:1px solid var(--s3);color:var(--t1);padding:7px 13px;border-radius:4px;cursor:pointer;font-weight:700}
.btn:hover{border-color:var(--acc)}.btn.pri{background:var(--acc);color:var(--accd);border-color:var(--acc)}.btn.red{background:#3a1d22;border-color:var(--red);color:#ffd0d5}
.btn:disabled{opacity:.4;cursor:default}
input,select,textarea{background:var(--bg);border:1px solid var(--s3);color:var(--t1);padding:9px 11px;border-radius:4px;width:100%}
input:focus,textarea:focus{outline:none;border-color:var(--acc)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.muted{color:var(--t3)}.mono{font-family:ui-monospace,Consolas,monospace;direction:ltr;unicode-bidi:plaintext}
.login{max-width:420px;margin:12vh auto;text-align:center}.login .card{padding:28px}.login input{text-align:center;font-size:24px;letter-spacing:6px;font-weight:900;direction:ltr}
.err{color:var(--red);font-weight:700;min-height:22px}.ok{color:var(--acc);font-weight:700}
.feed{max-height:520px;overflow:auto}.feed div{padding:7px 0;border-bottom:1px solid var(--s2);font-size:14px}
canvas{background:#07090d;border:1px solid var(--s3);border-radius:6px;width:100%;max-width:640px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:900px){.cols{grid-template-columns:1fr}}
.tag{font-size:12px;color:var(--t3)}.w{font-weight:800}
</style></head><body><div id="app"></div>
<script>
const $=(s,r=document)=>r.querySelector(s);const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const api=async(p,b)=>{const r=await fetch(p,b?{method:"POST",headers:{"content-type":"application/json","x-tf":"1"},body:JSON.stringify(b)}:{});let j={};try{j=await r.json()}catch{}if(r.status===401&&p!=="/api/me"){me=null;render()}return{ok:r.ok,status:r.status,j}};
const ago=t=>{const s=Math.floor(Date.now()/1000)-t;if(s<60)return s+" ث";if(s<3600)return Math.floor(s/60)+" د";if(s<86400)return Math.floor(s/3600)+" س";return Math.floor(s/86400)+" يوم"};
const ST={open:"مفتوحة",review:"مراجعة",jailed:"سجن الظل",queued:"بموجة البان",banned:"محظور",cleared:"براءة",accepted:"مقبول",rejected:"مرفوض"};const st=x=>ST[x]||x;
const MODE={on:["on-p","شغّال"],shadow:["sh-p","مراقبة"],off:["off-p","طافي"],canary:["ca-p","تجربة"]};
const KIND={signal:"إشارة",case:"قضية",report:"بلاغ",kick:"طرد",evidence:"دليل",autoshadow:"فحص ذاتي",adminlog:"أمر أدمن",streamer:"ستريمر",webcmd:"أمر من الموقع",weblogin:"دخول الموقع"};
let me=null,tab="dash",timer=null;
const TABS=[["dash","الرئيسية",0],["players","اللاعبين",1],["ac","الحماية",1],["cases","القضايا والإعادة",2],["cmd","الأوامر",1],["streamers","الستريمرز",0],["owner","تحكم المالك",4],["appeals","الاستئنافات",3],["log","السجل",1]];
async function boot(){const r=await api("/api/me");me=r.ok?r.j:null;if(me&&me.rank<1)tab="streamers";render()}
function render(){clearInterval(timer);const a=$("#app");
 if(!me){a.innerHTML='<div class="login"><div class="logo" style="font-size:28px;margin-bottom:18px">TRIGGERS <b>FIGHTING</b></div><div class="card"><h2>دخول لوحة التحكم</h2><p class="muted">ادخل اللعبة واكتب <span class="mono">;weblogin</span> بالشات، وحط الكود هنا. الكود لمرة وحدة وينتهي بعد 10 دقايق.</p><input id="code" maxlength="8" placeholder="XXXXXXXX" autocomplete="one-time-code"><p class="err" id="e"></p><button class="btn pri" style="width:100%" id="go">دخول</button></div><p class="muted" style="margin-top:18px">عندك بان وتبي تستأنف؟ <a href="/appeal">قدّم استئناف</a></p></div>';
  const go=async()=>{const r=await api("/api/login",{code:$("#code").value});if(r.ok)boot();else $("#e").textContent=r.j.error||"صار خطأ"};$("#go").onclick=go;$("#code").onkeydown=e=>{if(e.key==="Enter")go()};return}
 a.innerHTML='<div class="top"><div class="logo">TRIGGERS <b>FIGHTING</b> <span class="muted" style="font-size:14px">· لوحة التحكم</span></div><div class="who">'+esc(me.name)+' · <span class="pill">'+esc(me.rankAr)+'</span> <button class="btn" id="out" style="margin-inline-start:8px">خروج</button></div></div><nav id="nav"></nav><main id="m"></main>';
 $("#out").onclick=async()=>{await api("/api/logout",{});me=null;render()};
 const nav=$("#nav");for(const[id,l,r]of TABS){if(me.rank<r)continue;if(id==="streamers"&&me.rank<1&&!me.streamer)continue;if(me.rank<1&&id!=="streamers")continue;const b=document.createElement("button");b.innerHTML="<span>"+l+"</span>";if(id===tab)b.className="on";b.onclick=()=>{tab=id;render()};nav.appendChild(b)}
 (PAGES[tab]||PAGES.dash)($("#m"))}
async function runCmd(line,target){const r=await api("/api/run",{line,target});if(!r.ok)return"ما انرسل: "+(r.j.error||r.status);for(let i=0;i<20;i++){await new Promise(z=>setTimeout(z,1500));const q=await api("/api/result/"+r.j.id);if(q.ok&&q.j.results.length)return q.j.results.map(x=>(x.job.slice(0,8)||"سيرفر")+": "+x.result).join("\\n")}return"انرسل للسيرفرات (ما فيه سيرفر رد خلال 30 ثانية — يمكن ما فيه سيرفرات شغالة)"}
const PAGES={
 async dash(m){const load=async()=>{const r=await api("/api/overview");if(!r.ok)return;const o=r.j;
  m.innerHTML='<div class="grid">'+[["سيرفرات شغالة",o.servers.length],["لاعبين الحين",o.players],["أوامر الأدمن",o.commands],["قضايا مفتوحة",o.openCases],["استئنافات تنتظر",o.openAppeals],["إشارات آخر ساعة",o.hour.signals],["بلاغات آخر ساعة",o.hour.reports],["طرد تلقائي آخر ساعة",o.hour.kicks]].map(([l,n])=>'<div class="card stat"><div class="n">'+esc(n)+'</div><div class="l">'+l+'</div></div>').join("")+'</div>'+
  '<h2>الحماية</h2><div class="card row"><span>العقوبات: '+(o.ac?(o.ac.enforce?'<span class="pill on-p">شغّالة</span>':'<span class="pill sh-p">مراقبة بس</span>'):'<span class="muted">ما فيه بيانات بعد</span>')+'</span><span>الطرد التلقائي: '+(o.ac?(o.ac.kick?'<span class="pill on-p">شغّال</span>':'<span class="pill off-p">طافي</span>'):'—')+'</span><span>موجة البان: '+(o.wave?(o.wave.queue+" بالطابور · تنزل بعد "+Math.max(0,Math.floor((o.wave.nextAt-Date.now()/1000)/60))+" دقيقة"):"—")+'</span></div>'+
  '<h2>السيرفرات</h2>'+(o.servers.length?'<table><tr><th>السيرفر</th><th>اللاعبين</th><th>شغال من</th><th>النسخة</th><th>آخر اتصال</th></tr>'+o.servers.map(s=>'<tr><td class="mono">'+esc(s.job.slice(0,13))+(s.studio?' <span class="pill">ستوديو</span>':'')+'</td><td>'+s.players+'</td><td>'+ago(Math.floor(Date.now()/1000)-s.uptime)+'</td><td>'+esc(s.version)+'</td><td>'+ago(s.seen)+'</td></tr>').join("")+'</table>':'<div class="card muted">ما فيه سيرفرات متصلة الحين. أول ما يدخل لاعب، السيرفر يتصل بالموقع تلقائياً.</div>')};
  await load();timer=setInterval(load,6000)},
 async players(m){const load=async()=>{const r=await api("/api/players");if(!r.ok)return;
  m.innerHTML='<h2>اللاعبين بكل السيرفرات ('+r.j.length+')</h2><table><tr><th>اللاعب</th><th>الرتبة</th><th>المستوى / SR</th><th>الثقة</th><th>الإشارات</th><th>البنق</th><th>الحالة</th><th></th></tr>'+r.j.map(p=>'<tr><td><b>'+esc(p.display)+'</b> <span class="tag">@'+esc(p.name)+' · '+p.id+'</span></td><td>'+(p.rank?esc(["","مساعد","مشرف","آدمن","مدير","مالك"][p.rank]):"")+(p.streamer?' <span class="pill ca-p">ستريمر</span>':'')+'</td><td>'+esc(p.level)+' / '+esc(p.sr)+'</td><td>'+esc(p.trust)+'</td><td>'+(p.score>0?'<span class="w" style="color:'+(p.score>=40?'var(--red)':'var(--gold)')+'">'+p.score+'</span>':'0')+'</td><td>'+p.ping+'ms</td><td>'+(p.match?'بماتش ':'لوبي ')+(p.jailed?'<span class="pill off-p">سجن الظل</span>':'')+(p.hidden?' <span class="pill">مخفي</span>':'')+'</td><td class="row">'+["spectate|تابع","evidence_take|دليل","kick|طرد","jail|سجن"].map(x=>{const[c,l]=x.split("|");return'<button class="btn" data-c="'+c+'" data-n="'+esc(p.name)+'" data-j="'+esc(p.job)+'">'+l+'</button>'}).join("")+'</td></tr>').join("")+'</table><p class="muted">الأزرار تنفذ الأمر على سيرفر اللاعب. التابع يشتغل بس إذا أنت داخل نفس السيرفر.</p>';
  m.querySelectorAll("[data-c]").forEach(b=>b.onclick=async()=>{b.disabled=true;const res=await runCmd(";"+b.dataset.c+" "+b.dataset.n,b.dataset.j);alert(res);b.disabled=false})};
  await load();timer=setInterval(load,8000)},
 async ac(m){const r=await api("/api/detectors");const d=r.j.detectors||{};const ids=Object.keys(d).sort((a,b)=>(d[a].cat||"").localeCompare(d[b].cat||"")||a.localeCompare(b));
  const can=me.rank>=4;
  const sh=r.j.shield;const fams=sh?Object.entries(sh.fams||{}).sort((a,b)=>b[1].n-a[1].n):[];
  m.innerHTML=(sh?'<h2>درع الحماية: '+sh.count+' قاعدة من '+sh.mechs+' آلية</h2><p class="muted">كل عائلة تقدر تغيّر وضعها كاملة. كل القواعد شغالة على كل السيرفرات، وتبدأ مراقبة.</p><table><tr><th>العائلة</th><th>القواعد</th><th>الوضع</th><th>الإشارات بالسيرفرات</th>'+(can?'<th>غيّر</th>':'')+'</tr>'+fams.map(([f,x])=>{const md=MODE[x.mode]||MODE.shadow;return'<tr><td><b>'+esc(x.ar)+'</b></td><td>'+x.n+'</td><td><span class="pill '+md[0]+'">'+md[1]+'</span></td><td>'+x.hits+'</td>'+(can?'<td class="row">'+["on","shadow","off","canary"].map(mo=>'<button class="btn" data-fam="'+f+'" data-m="'+mo+'"'+(mo===x.mode?" disabled":"")+'>'+MODE[mo][1]+'</button>').join("")+'</td>':'')+'</tr>'}).join("")+'</table>'+((sh.top||[]).length?'<h2>أكثر القواعد اشتغالاً</h2><div class="card">'+sh.top.map(t=>'<span class="pill" style="margin:3px">'+esc(t.ar||t.id)+' · '+t.n+'</span>').join("")+'</div>':''):'')+'<h2>الكواشف ('+ids.length+')</h2><p class="muted">كل كاشف: شغّال = يتدخل (يرجّع اللاعب أو يرمي الطلب) · مراقبة = يسجل بس · طافي · تجربة = على جزء من السيرفرات. التغيير ينطبق على كل السيرفرات.</p>'+
  (ids.length?'<table><tr><th>الكاشف</th><th>الفئة</th><th>الوضع</th><th>إشارات الدقيقة</th><th>المجموع</th><th>الأرقام</th>'+(can?'<th>غيّر</th>':'')+'</tr>'+ids.map(id=>{const x=d[id];const md=MODE[x.mode]||MODE.shadow;return'<tr><td><b>'+esc(x.ar)+'</b><div class="tag mono">'+esc(id)+'</div></td><td>'+esc(x.cat)+'</td><td><span class="pill '+md[0]+'">'+md[1]+'</span></td><td>'+x.minute+'</td><td>'+x.stats+'</td><td class="tag mono">'+esc(Object.entries(x.params||{}).map(([k,v])=>k+"="+v).join(" "))+'</td>'+(can?'<td class="row">'+["on","shadow","off","canary"].map(mo=>'<button class="btn" data-id="'+id+'" data-m="'+mo+'"'+(mo===x.mode?" disabled":"")+'>'+MODE[mo][1]+'</button>').join("")+'</td>':'')+'</tr>'}).join("")+'</table>':'<div class="card muted">الكواشف تطلع هنا أول ما يتصل سيرفر.</div>')+
  '<h2>آخر الإشارات</h2><div class="card feed" id="feed">...</div>';
  m.querySelectorAll("[data-m]").forEach(b=>b.onclick=async()=>{if(b.dataset.m==="on"&&!confirm("التشغيل يخليها تتدخل. متأكد؟"))return;b.disabled=true;await runCmd(b.dataset.fam?";shield_"+b.dataset.fam+"_"+b.dataset.m:";ac_"+b.dataset.id+"_"+b.dataset.m);PAGES.ac(m)});
  const feed=async()=>{const e=await api("/api/events?k=signal,kick,autoshadow,evidence,report");if(!e.ok)return;$("#feed").innerHTML=e.j.slice(0,150).map(x=>'<div><span class="muted">'+ago(x.t)+'</span> · <b>'+esc(KIND[x.k]||x.k)+'</b> · '+esc(x.d?.name||x.d?.target||x.d?.killer?.name||x.d?.id||"")+' · <span class="mono">'+esc(x.d?.detail||x.d?.why||x.d?.reason||(x.d?.flags?x.d.flags+" إشارة":""))+'</span>'+(x.d?.w?' <span class="pill">+'+x.d.w+'</span>':'')+(x.d?.ping?' <span class="tag">'+x.d.ping+'ms</span>':'')+'</div>').join("")||'<span class="muted">ما فيه إشارات</span>'};
  await feed();timer=setInterval(feed,6000)},
 async cases(m){const r=await api("/api/cases");
  m.innerHTML='<div class="row"><h2 style="margin:0">القضايا</h2><button class="btn" id="rf">جيب القضايا القديمة من اللعبة</button></div><div class="cols" style="margin-top:12px"><div><table><tr><th>#</th><th>اللاعب</th><th>السبب</th><th>الحالة</th><th>الوقت</th></tr>'+(r.j||[]).map(c=>'<tr style="cursor:pointer" data-id="'+c.id+'"><td class="mono">'+c.id+'</td><td>'+esc(c.name)+'</td><td>'+esc(c.reason)+'</td><td><span class="pill">'+esc(st(c.status))+'</span></td><td>'+ago(c.t)+'</td></tr>').join("")+'</table></div><div id="cv" class="card muted">اختر قضية تشوف الإعادة والدليل.</div></div>';
  $("#rf").onclick=async()=>{await api("/api/cases/refresh",{});setTimeout(()=>PAGES.cases(m),8000);$("#rf").textContent="ينجاب..."};
  m.querySelectorAll("[data-id]").forEach(t=>t.onclick=()=>showCase(t.dataset.id))},
 async cmd(m){m.innerHTML='<h2>تنفيذ أمر</h2><div class="card"><div class="row"><input id="ln" class="mono" placeholder=";announce هلا بالجميع" style="flex:1"><select id="tg" style="width:220px"><option value="all">كل السيرفرات</option></select><button class="btn pri" id="go">نفّذ</button></div><p class="muted">أي أمر من أوامر اللعبة (الـ 1000+). الرتبة تنشيك بالموقع وباللعبة. الأوامر اللي تحتاج لاعب لازم يكون اللاعب بنفس السيرفر.</p><pre id="res" class="mono" style="white-space:pre-wrap"></pre></div><h2>أوامر سريعة</h2><div class="row" id="quick"></div>';
  const o=await api("/api/overview");for(const s of o.j.servers||[]){const op=document.createElement("option");op.value=s.job;op.textContent="سيرفر "+s.job.slice(0,8)+" ("+s.players+")";$("#tg").appendChild(op)}
  const go=async()=>{$("#res").textContent="ينفّذ...";$("#res").textContent=await runCmd($("#ln").value,$("#tg").value)};$("#go").onclick=go;$("#ln").onkeydown=e=>{if(e.key==="Enter")go()};
  for(const[l,c]of[["معلومات السيرفرات",";serverinfo"],["الكواشف",";detectors"],["صحة الكواشف",";ac_health"],["البلاغات",";reports"],["الأدلة",";evidence"],["الأنظمة الموقفة",";kill_list"],["الفعالية",";event_status"],["الستريمرز",";streamer_list"],["موجة البان",";wave info"]]){const b=document.createElement("button");b.className="btn";b.textContent=l;b.onclick=()=>{$("#ln").value=c;go()};$("#quick").appendChild(b)}},
 async streamers(m){const r=await api("/api/streamers");if(!r.ok){m.innerHTML='<div class="card">ما عندك صلاحية</div>';return}const S=r.j.streamers||{};const off=Object.keys(r.j.perkOff||{});const own=me.rank>=4;
  m.innerHTML='<h2>الستريمرز ('+Object.keys(S).length+')</h2>'+(own?'<div class="card row"><input id="sid" class="mono" placeholder="رقم حساب روبلوكس" style="width:220px"><select id="stier" style="width:120px"><option>1</option><option>2</option><option>3</option></select><button class="btn pri" id="sadd">أضف ستريمر</button><span class="muted">الإضافة تنطبق بكل السيرفرات.</span></div>':'')+
  '<table style="margin-top:12px"><tr><th>الستريمر</th><th>الفئة</th><th>من</th><th>رصيد الهدايا</th><th>أهدى</th><th>شكله</th>'+(own?'<th></th>':'')+'</tr>'+Object.entries(S).map(([id,s])=>'<tr><td><b>'+esc(s.name||id)+'</b> <span class="tag">'+id+'</span></td><td>'+esc(s.tier)+'</td><td>'+(s.since?ago(s.since):"")+'</td><td>'+esc(s.budget)+'</td><td>'+esc(s.gifted||0)+'</td><td class="tag mono">'+esc(Object.values(s.sel||{}).join(" "))+'</td>'+(own?'<td><button class="btn red" data-rm="'+id+'">شيل</button></td>':'')+'</tr>').join("")+'</table>'+
  (own?'<h2>الحصريات المقفولة ('+off.length+' من 200)</h2><div class="card">'+(off.length?off.map(x=>'<span class="pill off-p" style="margin:3px">'+esc(x)+' <button class="btn" style="padding:0 6px" data-on="'+esc(x)+'">افتح</button></span>').join(""):'<span class="muted">كل الـ 200 مفتوحة</span>')+'<div class="row" style="margin-top:12px"><input id="pk" class="mono" placeholder="اسم الحصرية مثل trail_purple" style="width:300px"><button class="btn red" id="pkoff">اقفلها للكل</button></div></div>':'')+
  '<h2>نشاطات الستريمرز</h2><div class="card feed">'+(r.j.activity||[]).map(e=>'<div><span class="muted">'+ago(e.t)+'</span> · <b>'+esc(e.d?.name)+'</b> · '+esc(e.d?.what)+' <span class="mono">'+esc(e.d?.detail)+'</span></div>').join("")+'</div>';
  if(own){$("#sadd").onclick=async()=>{const id=$("#sid").value.trim();if(!/^\\d+$/.test(id))return alert("رقم الحساب أرقام بس");alert(await runCmd(";streamer_addid "+id+" "+$("#stier").value));PAGES.streamers(m)};
   m.querySelectorAll("[data-rm]").forEach(b=>b.onclick=async()=>{if(!confirm("تشيل رتبة الستريمر؟"))return;alert(await runCmd(";streamer_removeid "+b.dataset.rm));PAGES.streamers(m)});
   m.querySelectorAll("[data-on]").forEach(b=>b.onclick=async()=>{alert(await runCmd(";sperk_"+b.dataset.on+" on"));PAGES.streamers(m)});
   $("#pkoff").onclick=async()=>{const k=$("#pk").value.trim();if(!/^[a-z0-9_:]+$/.test(k))return;alert(await runCmd(";sperk_"+k+" off"));PAGES.streamers(m)}}},
 async owner(m){const o=await api("/api/overview");const ac=o.j.ac||{};const kill=ac.kill||{};
  const F=[["shop","المتجر"],["rewards","المكافآت والمهام"],["pass","الباتل باس"],["gunsmith","الغانسميث"],["wardrobe","الملابس والسكنات"],["clans","الكلانات"],["party","الفريق"],["duels","الدويلات"],["respect","الاحترام"],["gifts","هدايا الستريمرز"],["ranked","الرانكد"],["custom","القيمات الخاصة"]];
  m.innerHTML='<h2>قاطع الكهرباء</h2><p class="muted">أي نظام فيه مشكلة أو ثغرة توقفه فوراً بكل السيرفرات، وترجعه بضغطة.</p><div class="grid">'+F.map(([k,l])=>'<div class="card row"><b style="flex:1">'+l+'</b>'+(kill[k]?'<span class="pill off-p">موقف</span><button class="btn pri" data-k="'+k+'" data-v="off">شغّل</button>':'<span class="pill on-p">شغال</span><button class="btn red" data-k="'+k+'" data-v="on">أوقف</button>')+'</div>').join("")+'</div>'+
  '<h2>الحماية</h2><div class="card row"><span style="flex:1">العقوبات (سجن الظل + موجات البان): '+(ac.enforce?'<span class="pill on-p">شغّالة</span>':'<span class="pill sh-p">مراقبة بس</span>')+'</span>'+(me.rank>=5?'<button class="btn '+(ac.enforce?"":"red")+'" id="enf">'+(ac.enforce?"رجّعها مراقبة":"فعّل العقوبات")+'</button>':'')+'</div>'+
  '<div class="card row" style="margin-top:10px"><span style="flex:1">الطرد التلقائي (أكثر من 10 مخالفات واضحة بالدقيقة): '+(ac.kick?'<span class="pill on-p">شغّال</span>':'<span class="pill off-p">طافي</span>')+'</span><button class="btn" id="kk">'+(ac.kick?"طفّه":"شغّله")+'</button></div>'+
  '<div class="card row" style="margin-top:10px"><span style="flex:1">موجة البان: '+(o.j.wave?o.j.wave.queue+" بالطابور":"—")+'</span><button class="btn red" id="wv">نزّل الموجة الحين</button></div>'+
  '<h2>فعالية جوايز</h2><div class="card row"><select id="ev" style="width:140px"><option value="x1_5">×1.5</option><option value="x2">×2</option><option value="x3">×3</option></select><input id="evm" type="number" value="60" style="width:110px"><span class="muted">دقيقة</span><button class="btn pri" id="evgo">ابدأ بكل السيرفرات</button><button class="btn" id="evoff">أوقف</button></div>'+
  '<h2>إعلان لكل السيرفرات</h2><div class="card row"><input id="an" placeholder="نص الإعلان" style="flex:1"><button class="btn pri" id="ango">أرسل</button></div>'+
  (me.rank>=5?'<h2>جلسات الموقع</h2><div class="card" id="ses">...</div>':'');
  const act=async(line,ask)=>{if(ask&&!confirm(ask))return;alert(await runCmd(line));PAGES.owner(m)};
  m.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>act(";kill_"+b.dataset.k+" "+b.dataset.v,b.dataset.v==="on"?"توقف هالنظام بكل السيرفرات؟":null));
  if($("#enf"))$("#enf").onclick=()=>act(";enforce "+(ac.enforce?"off":"on"),ac.enforce?null:"تفعيل العقوبات يعني سجن الظل وموجات البان تشتغل فعلياً. متأكد؟");
  $("#kk").onclick=()=>act(";ac_kick "+(ac.kick?"off":"on"));$("#wv").onclick=()=>act(";wave now","تنزل كل البانات اللي بالطابور الحين؟");
  $("#evgo").onclick=()=>act(";event_"+$("#ev").value+" "+Number($("#evm").value||60));$("#evoff").onclick=()=>act(";event_off");
  $("#ango").onclick=()=>{const t=$("#an").value.trim();if(t)act(";announce "+t)};
  if(me.rank>=5){const s=await api("/api/sessions");$("#ses").innerHTML=(s.j||[]).map(x=>'<div>'+esc(x.name)+' · '+esc(["ستريمر","مساعد","مشرف","آدمن","مدير","مالك"][x.rank])+(x.me?' <span class="pill on-p">أنت</span>':'')+'</div>').join("")+'<button class="btn red" id="rv" style="margin-top:10px">اطرد كل الجلسات غيري</button>';$("#rv").onclick=async()=>{await api("/api/sessions/revoke",{});PAGES.owner(m)}}},
 async appeals(m){const r=await api("/api/appeals");
  m.innerHTML='<h2>الاستئنافات</h2><p class="muted">رابط الاستئناف للاعبين: <span class="mono">'+location.origin+'/appeal</span> · قبول الاستئناف يفك البان (مدير ومالك).</p><table><tr><th>#</th><th>القضية</th><th>اللاعب</th><th>الرسالة</th><th>الحالة</th><th></th></tr>'+(r.j||[]).map(a=>'<tr><td>'+a.id+'</td><td><a href="#" data-case="'+a.caseId+'">#'+a.caseId+'</a></td><td>'+esc(a.username)+'</td><td style="max-width:420px">'+esc(a.message)+'</td><td><span class="pill">'+esc(st(a.status))+'</span>'+(a.by?'<div class="tag">'+esc(a.by)+'</div>':'')+'</td><td class="row">'+(a.status==="open"?'<button class="btn pri" data-a="'+a.id+'" data-v="1">اقبل وفك البان</button><button class="btn red" data-a="'+a.id+'" data-v="0">ارفض</button>':'')+'</td></tr>').join("")+'</table><div id="cv" class="card" style="margin-top:14px;display:none"></div>';
  m.querySelectorAll("[data-a]").forEach(b=>b.onclick=async()=>{const note=prompt("ملاحظة (اختياري)")||"";const x=await api("/api/appeal/decide",{id:Number(b.dataset.a),accept:b.dataset.v==="1",note});if(!x.ok)alert(x.j.error);PAGES.appeals(m)});
  m.querySelectorAll("[data-case]").forEach(a=>a.onclick=e=>{e.preventDefault();$("#cv").style.display="block";showCase(a.dataset.case)})},
 async log(m){const r=await api("/api/events?k=adminlog,webcmd,weblogin,kick,autoshadow");
  m.innerHTML='<h2>السجل</h2><table><tr><th>الوقت</th><th>النوع</th><th>مين</th><th>الأمر</th><th>النتيجة</th></tr>'+(r.j||[]).map(e=>'<tr><td>'+ago(e.t)+'</td><td>'+esc(KIND[e.k]||e.k)+'</td><td>'+esc(e.d?.by||e.d?.name||"")+'</td><td class="mono">'+esc(e.d?.line||e.d?.why||e.d?.id||"")+'</td><td>'+esc(e.d?.result||"")+'</td></tr>').join("")+'</table>'}
};
async function showCase(id){const cv=$("#cv");cv.className="card";cv.innerHTML="ينجاب...";let c;for(let i=0;i<8;i++){const r=await api("/api/case/"+id);c=r.j;if(c&&c.frames)break;cv.innerHTML="نجيب القضية من اللعبة... ("+(i+1)+")";await new Promise(z=>setTimeout(z,3000))}
 if(!c||!c.frames){cv.innerHTML="ما قدرنا نجيب الإعادة (يمكن ما فيه سيرفر شغال الحين). "+esc(JSON.stringify(c||{}).slice(0,300));return}
 const can=me.rank>=3;
 cv.innerHTML='<div class="row"><h2 style="margin:0">قضية #'+c.id+'</h2><span class="pill">'+esc(st(c.status))+'</span></div><p><b>'+esc(c.display||c.name)+'</b> <span class="tag">@'+esc(c.name)+' · '+c.userId+'</span> · '+esc(c.reason)+'</p><p class="muted">النقاط '+c.score+' · الثقة '+esc(c.trust)+' · عمر الحساب '+esc(c.accountAge)+' يوم · نسخة '+esc(c.place)+'</p>'+
 '<canvas id="cvs" width="640" height="420"></canvas><div class="row"><button class="btn" id="pl">▶ شغّل الإعادة</button><span class="muted">الأخضر = المتهم · الخطوط = طلقاته · آخر 10 ثواني</span></div>'+
 '<h2>الإشارات</h2><div class="feed">'+(c.signals||[]).map(s=>'<div>'+esc(s.cat)+' +'+s.weight+' · <span class="mono">'+esc(s.detail)+'</span> <span class="tag">'+s.ping+'ms</span></div>').join("")+'</div>'+
 (c.aim?'<p>الإيم: '+c.aim.shots+' طلقة · '+c.aim.hits+' إصابة · '+c.aim.heads+' هيد</p>':'')+
 '<h2>الملاحظات</h2>'+(c.notes||[]).map(n=>'<div class="tag">'+esc(n.by)+' → '+esc(st(n.status))+' '+esc(n.note||"")+'</div>').join("")+
 (can?'<div class="row" style="margin-top:12px"><input id="nt" placeholder="ملاحظة" style="flex:1"><button class="btn pri" data-d="clear">براءة</button><button class="btn" data-d="jail">سجن الظل</button><button class="btn red" data-d="wave">لموجة البان</button></div>':'');
 cv.querySelectorAll("[data-d]").forEach(b=>b.onclick=async()=>{if(b.dataset.d==="wave"&&!confirm("تضيفه لموجة البان؟"))return;await api("/api/decide",{caseId:c.id,what:b.dataset.d,note:$("#nt").value});setTimeout(()=>showCase(c.id),6000);b.textContent="انرسل"});
 const cvs=$("#cvs"),g=cvs.getContext("2d");const fr=c.frames||{};const ids=Object.keys(fr);let mnx=1e9,mxx=-1e9,mnz=1e9,mxz=-1e9;for(const k of ids)for(const f of fr[k]){mnx=Math.min(mnx,f[0]);mxx=Math.max(mxx,f[0]);mnz=Math.min(mnz,f[2]);mxz=Math.max(mxz,f[2])}
 const pad=30,sc=Math.min((640-pad*2)/Math.max(10,mxx-mnx),(420-pad*2)/Math.max(10,mxz-mnz));const X=x=>pad+(x-mnx)*sc,Z=z=>pad+(z-mnz)*sc;const n=Math.max(...ids.map(k=>fr[k].length),1);
 const draw=i=>{g.fillStyle="#07090d";g.fillRect(0,0,640,420);for(const k of ids){const L=fr[k];const sus=String(k)===String(c.userId);g.strokeStyle=sus?"rgba(61,220,107,.35)":"rgba(174,182,177,.18)";g.beginPath();L.slice(0,i+1).forEach((f,j)=>j?g.lineTo(X(f[0]),Z(f[2])):g.moveTo(X(f[0]),Z(f[2])));g.stroke();const f=L[Math.min(i,L.length-1)];if(!f)continue;g.fillStyle=sus?"#3DDC6B":"#4DA3FF";g.beginPath();g.arc(X(f[0]),Z(f[2]),sus?6:4,0,7);g.fill();g.strokeStyle=g.fillStyle;g.beginPath();g.moveTo(X(f[0]),Z(f[2]));g.lineTo(X(f[0])+Math.sin(f[3])*14,Z(f[2])+Math.cos(f[3])*14);g.stroke()}
  for(const s of(c.shots||[]).slice(-Math.ceil((i+1)/n*(c.shots||[]).length))){g.strokeStyle=s.head?"#FF4D5E":"#F5C542";g.globalAlpha=.6;g.beginPath();g.moveTo(X(s.o[0]),Z(s.o[2]));g.lineTo(X(s.h[0]),Z(s.h[2]));g.stroke();g.globalAlpha=1}
  g.fillStyle="#6B7A71";g.font="12px Tajawal";g.fillText((i/5).toFixed(1)+"s / "+(n/5).toFixed(1)+"s",10,412)};
 draw(n-1);$("#pl").onclick=()=>{let i=0;const t=setInterval(()=>{draw(i);i++;if(i>=n)clearInterval(t)},200)}}
boot();
</script></body></html>`;

const APPEAL = /* html */ `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>استئناف الحظر · Triggers Fighting</title>
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;700;900&display=swap" rel="stylesheet">
<style>body{margin:0;background:#0B0D12;color:#F2F5F3;font-family:Tajawal,system-ui,sans-serif}.w{max-width:520px;margin:8vh auto;padding:0 16px}.c{background:#121620;border:1px solid #272E3D;border-radius:6px;padding:24px}
h1{font-weight:900}h1 b{color:#3DDC6B}label{display:block;margin:14px 0 6px;font-weight:700;color:#AEB6B1}input,textarea{width:100%;box-sizing:border-box;background:#0B0D12;border:1px solid #272E3D;color:#F2F5F3;padding:10px;border-radius:4px;font:inherit}
textarea{min-height:140px}button{margin-top:16px;width:100%;background:#3DDC6B;color:#06210F;border:0;padding:12px;border-radius:4px;font:inherit;font-weight:900;cursor:pointer}.m{margin-top:12px;font-weight:700}</style></head>
<body><div class="w"><h1>TRIGGERS <b>FIGHTING</b></h1><div class="c"><h2>استئناف الحظر</h2><p style="color:#AEB6B1">رقم القضية مكتوب برسالة الحظر لما تحاول تدخل اللعبة. الإدارة تراجع الدليل وترد.</p>
<label>رقم القضية</label><input id="c" inputmode="numeric"><label>اسمك بروبلوكس</label><input id="u"><label>وش صار؟</label><textarea id="t" maxlength="1500"></textarea><button id="go">أرسل الاستئناف</button><div class="m" id="m"></div></div></div>
<script>document.getElementById("go").onclick=async()=>{const r=await fetch("/api/appeal",{method:"POST",headers:{"content-type":"application/json","x-tf":"1"},body:JSON.stringify({caseId:Number(c.value.replace(/\\D/g,"")),username:u.value,message:t.value})});const j=await r.json().catch(()=>({}));m.style.color=r.ok?"#3DDC6B":"#FF4D5E";m.textContent=r.ok?"وصل استئنافك. الإدارة بتراجعه.":(j.error||"صار خطأ")}</script></body></html>`;

// ---------------------------------------------------------------- السيرفر
await load();
const server = Bun.serve({
  port: PORT,
  async fetch(req, srv) {
    const url = new URL(req.url);
    try {
      if (url.pathname === "/api/game/sync" && req.method === "POST") return await gameSync(req);
      if (url.pathname === "/health") return new Response("ok");
      if (url.pathname.startsWith("/api/")) return await api(req, url, srv);
      if (url.pathname === "/appeal") return new Response(APPEAL, { headers: { "content-type": "text/html; charset=utf-8", ...SEC_HEADERS } });
      if (url.pathname === "/") return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8", ...SEC_HEADERS } });
      return new Response("not found", { status: 404 });
    } catch (e) {
      console.error(e);
      return json({ error: "server" }, 500);
    }
  },
});
console.log(`[TF] لوحة التحكم شغالة على ${server.port} · حفظ: ${HAS_DB ? "Postgres" : LOCAL_FILE} · مفتاح اللعبة: ${GAME_KEY ? "موجود" : "ناقص!"}`);
for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, async () => { dirty = true; await save(); process.exit(0); });
