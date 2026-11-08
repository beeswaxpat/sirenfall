// The note: a visitor pins a few words for the makers on the shelter wall (POST /note). One D1 database (binding DB), same as the door.
// Private by design: there is NO route that returns a note. They are read only by the makers, straight from the database.
// No IP address is stored. The only per-visitor record is a hash of the address (an IPv6 address by its /64) that changes every UTC day
// and is deleted when that day is over. Limits: 3 notes per address and 200 notes in all per UTC day.

const TEXT_MAX = 1000, BODY_MAX = 4096, PER_ADDR_DAY = 3, DAY_MAX = 200;
const SITE = "https://sirenfall.live";
const LOCAL = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/; // local tests only
// control characters (newlines stay), bidi overrides and line/paragraph separators: nothing that could scramble how a note reads later
const JUNK = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/g;

let inited = false;
async function init(db) {
  if (inited) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, created INTEGER NOT NULL, lang TEXT NOT NULL, text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new')"),
    db.prepare("CREATE INDEX IF NOT EXISTS notes_created ON notes (created)"),
    db.prepare("CREATE TABLE IF NOT EXISTS note_hits (h TEXT NOT NULL, t INTEGER NOT NULL)"),
    db.prepare("CREATE INDEX IF NOT EXISTS note_hits_h ON note_hits (h)"),
    db.prepare("CREATE TABLE IF NOT EXISTS note_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)"),
  ]);
  inited = true;
}

const now = () => Math.floor(Date.now() / 1000);
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const sha = async s => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
function randId(n) {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", b = crypto.getRandomValues(new Uint8Array(n));
  return [...b].map(x => a[x % a.length]).join("");
}
async function secret(db) {
  await db.prepare("INSERT OR IGNORE INTO note_meta (k, v) VALUES ('secret', ?)").bind(randId(40)).run();
  return (await db.prepare("SELECT v FROM note_meta WHERE k = 'secret'").first()).v;
}
function netOf(ip) { // an IPv6 address counts by its /64, so one machine cannot step through its own block
  if (ip.indexOf(":") < 0) return ip;
  let [a, b = ""] = ip.toLowerCase().split("::");
  const head = a ? a.split(":") : [], tail = b ? b.split(":") : [];
  const full = ip.indexOf("::") >= 0 ? head.concat(Array(Math.max(0, 8 - head.length - tail.length)).fill("0"), tail) : head;
  return full.slice(0, 4).map(h => h.replace(/^0+(?=.)/, "")).join(":") + "::/64";
}
async function addrHash(req, sec) {
  const ip = netOf(req.headers.get("CF-Connecting-IP") || "local"), day = new Date().toISOString().slice(0, 10);
  return (await sha(sec + "|" + day + "|" + ip)).slice(0, 32);
}

function reply(ok, status = 200, extra) {
  const h = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex" }; // no CORS header: same origin only
  if (extra) Object.assign(h, extra);
  return new Response(JSON.stringify({ ok }), { status, headers: h });
}
async function readBody(req) { // at most BODY_MAX bytes, however the length is announced
  const cl = parseInt(req.headers.get("Content-Length") || "0", 10);
  if (cl > BODY_MAX) return null;
  if (!req.body) return "";
  const rd = req.body.getReader(), parts = []; let n = 0;
  for (;;) {
    const { done, value } = await rd.read();
    if (done) break;
    n += value.length;
    if (n > BODY_MAX) { try { await rd.cancel(); } catch (e) {} return null; }
    parts.push(value);
  }
  const all = new Uint8Array(n); let o = 0;
  for (const p of parts) { all.set(p, o); o += p.length; }
  return new TextDecoder().decode(all);
}

export async function handle({ request: req, env }) {
  if (req.method !== "POST") return reply(false, 405, { Allow: "POST" });
  const origin = req.headers.get("Origin");
  if (origin !== null && origin !== SITE && !LOCAL.test(origin)) return reply(false, 403);
  const raw = await readBody(req);
  if (raw === null) return reply(false, 413);
  let b; try { b = JSON.parse(raw); } catch (e) { return reply(false, 400); }
  if (!b || typeof b !== "object" || Array.isArray(b)) return reply(false, 400);
  if (b.hp != null && String(b.hp) !== "") return reply(true); // the hidden field only a bot fills: thanked, stored nowhere
  if (typeof b.text !== "string") return reply(false, 400);
  const text = b.text.replace(/\r\n?/g, "\n").replace(JUNK, "").trim();
  if (text.length < 1 || text.length > TEXT_MAX) return reply(false, 400);
  const lang = typeof b.lang === "string" && /^[a-zA-Z-]{2,10}$/.test(b.lang) ? b.lang : "en";
  const db = env && env.DB;
  if (!db) return reply(false, 500);
  try {
    await init(db);
    const sec = await secret(db), t = now(), day0 = Math.floor(t / 86400) * 86400, by = await addrHash(req, sec), id = randId(12);
    const r = await db.batch([
      db.prepare("DELETE FROM note_hits WHERE t < ?").bind(day0), // yesterday's hashes go
      // one statement checks both limits and stores the note, so two fast posts cannot both slip past the last place
      db.prepare("INSERT INTO notes (id, created, lang, text) SELECT ?1, ?2, ?3, ?4 WHERE (SELECT COUNT(*) FROM note_hits WHERE h = ?5 AND t >= ?6) < ?7 AND (SELECT COUNT(*) FROM notes WHERE created >= ?6) < ?8 RETURNING id")
        .bind(id, t, lang, text, by, day0, PER_ADDR_DAY, DAY_MAX),
      db.prepare("INSERT INTO note_hits (h, t) SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM notes WHERE id = ?3)").bind(by, t, id),
    ]);
    return r[1].results && r[1].results.length ? reply(true) : reply(false, 429);
  } catch (e) { return reply(false, 500); }
}
