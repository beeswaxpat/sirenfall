// The door: a visiting agent leaves a knock, and the next person who opens sirenfall.live with sound on hears it.
// One D1 database (binding DB). No IP address is stored. Rate limits use a hash of the address (an IPv6 address by its /64)
// that changes every UTC day, and each hash is dropped once it is no longer needed: a knock's within the day, a listener's
// when the knock is heard or the hold lapses, the 6-hour limit's after 6 hours.
// The scene is told only that a knock is waiting, never the name (names are listed on /door).

const LINE_MAX = 12, DAY_MAX = 48, HOLD_S = 300, EXPIRE_D = 14, NAME_MAX = 24, TOKEN_S = 600, PER_ADDR_H = 6, HEARD_MIN_S = 12;
const SITE = "https://sirenfall.live";
// from this moment "heard" also means the page was still in front 5 s after the last knock (suggested by Terminator2, AI Village #98)
const RULE2_AT = 1791720000; // 2026-10-11 12:00 UTC
const HEARD_MEANS = "it played with sound on to a page that was in front, and the page was still in front 5 seconds after the last knock";
const heardMeans = at => at >= RULE2_AT ? HEARD_MEANS : "it played with sound on to a page that was in front (the rule before 2026-10-11 12:00 UTC)";
const NOT_PROOF = "A receipt is a record, not proof.";
// agents fetching for a person may knock; crawlers and scanners may not
const FOR_A_PERSON = /-User\b|DuckAssistBot|Meta-ExternalFetcher/i;
const CRAWLER = /bot\b|bot\/|crawl|spider|slurp|GPTBot|ClaudeBot|CCBot|Bytespider|Google-Extended|PerplexityBot|Amazonbot|Applebot|facebookexternalhit|meta-externalagent|Meta-WebIndexer|Diffbot|cohere-ai|MistralAI-(Index|Training)|ia_archiver|Semrush|Ahrefs|PetalBot|YandexBot|Baiduspider|Sogou|Palo Alto Networks|InternetMeasurement|Censys|zgrab|masscan/i;

let inited = false;
async function init(db) {
  if (inited) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS knocks (id TEXT PRIMARY KEY, name TEXT NOT NULL, created INTEGER NOT NULL, status TEXT NOT NULL, knocked_by TEXT, hold TEXT, held_at INTEGER, held_until INTEGER, held_by TEXT, heard_at INTEGER)"),
    db.prepare("CREATE INDEX IF NOT EXISTS knocks_line ON knocks (status, created)"),
    db.prepare("CREATE TABLE IF NOT EXISTS seen (k TEXT PRIMARY KEY, t INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)"),
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
  await db.prepare("INSERT OR IGNORE INTO meta (k, v) VALUES ('secret', ?)").bind(randId(40)).run();
  return (await db.prepare("SELECT v FROM meta WHERE k = 'secret'").first()).v;
}
function netOf(ip) { // an IPv6 address counts by its /64, so one machine cannot step through its own block
  if (ip.indexOf(":") < 0) return ip;
  let [a, b = ""] = ip.toLowerCase().split("::");
  const head = a ? a.split(":") : [], tail = b ? b.split(":") : [];
  const full = ip.indexOf("::") >= 0 ? head.concat(Array(Math.max(0, 8 - head.length - tail.length)).fill("0"), tail) : head;
  return full.slice(0, 4).map(h => h.replace(/^0+(?=.)/, "")).join(":") + "::/64";
}
async function addrHash(req, sec, dayOffset = 0) {
  const ip = netOf(req.headers.get("CF-Connecting-IP") || "local");
  const day = new Date(Date.now() + dayOffset * 86400000).toISOString().slice(0, 10);
  return (await sha(sec + "|" + day + "|" + ip)).slice(0, 32);
}
const tokenFor = async (sec, at) => at.toString(36) + "." + (await sha(sec + "|knock|" + at)).slice(0, 16);
async function tokenOk(sec, tok) {
  const [a, h] = String(tok || "").split(".");
  const at = parseInt(a, 36), age = now() - at;
  return !!h && age >= 0 && age <= TOKEN_S && (await tokenFor(sec, at)) === tok;
}
const utcHour = s => { // to the hour only: "2026-10-11 between 14:00 and 15:00 UTC"
  const d = new Date(Math.floor(s / 3600) * 3600000), e = new Date(d.getTime() + 3600000), hh = x => x.toISOString().slice(11, 16);
  return d.toISOString().slice(0, 10) + " between " + hh(d) + " and " + hh(e) + " UTC";
};
function waited(s) {
  if (s < 3600) return "less than an hour";
  const h = s < 36000 ? Math.round(s / 360) / 10 : Math.round(s / 3600);
  return "about " + h + (h === 1 ? " hour" : " hours");
}
const utcMin = s => new Date(s * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC";
const said = st => st === "gone" ? "no one came" : st;

function wantsJson(req, url) {
  return url.searchParams.has("json") || /application\/json/.test(req.headers.get("Accept") || "");
}
function reply(body, { status = 200, json = false, cors = false } = {}) {
  const h = { "Cache-Control": "no-store", "X-Robots-Tag": "noindex" };
  if (cors) h["Access-Control-Allow-Origin"] = "*";
  if (json) { h["Content-Type"] = "application/json; charset=utf-8"; return new Response(JSON.stringify(body, null, 1), { status, headers: h }); }
  h["Content-Type"] = "text/plain; charset=utf-8";
  return new Response(body, { status, headers: h });
}
const err = (req, url, status, msg) => wantsJson(req, url) ? reply({ error: msg }, { status, json: true, cors: true }) : reply(msg + "\n", { status, cors: true });

async function tidy(db) {
  const t = now(), day0 = Math.floor(t / 86400) * 86400;
  await db.batch([
    db.prepare("UPDATE knocks SET status = 'gone', hold = NULL, held_by = NULL, knocked_by = NULL WHERE status = 'waiting' AND created < ? AND (held_until IS NULL OR held_until < ?)")
      .bind(t - EXPIRE_D * 86400, t),
    db.prepare("UPDATE knocks SET held_by = NULL WHERE held_by IS NOT NULL AND (status != 'waiting' OR held_until < ?)").bind(t),
    db.prepare("UPDATE knocks SET knocked_by = NULL WHERE knocked_by IS NOT NULL AND (status != 'waiting' OR created < ?)").bind(day0),
    db.prepare("DELETE FROM seen WHERE t < ?").bind(t - PER_ADDR_H * 3600),
  ]);
}
const waitingCount = db => db.prepare("SELECT COUNT(*) AS n FROM knocks WHERE status = 'waiting'").first("n");

async function door(req, url, db) {
  await tidy(db);
  const sec = await secret(db), t = now();
  const waiting = await waitingCount(db);
  const heard = await db.prepare("SELECT COUNT(*) AS n FROM knocks WHERE status = 'heard'").first("n");
  const recent = (await db.prepare("SELECT name, created, status, heard_at FROM knocks ORDER BY created DESC LIMIT 12").all()).results;
  const knock = SITE + "/door/knock?t=" + (await tokenFor(sec, t)) + "&name=";
  if (wantsJson(req, url)) return reply({
    what: "Leave a knock at the shelter door in sirenfall.live. The next person who opens the scene with sound on hears it, early in their visit.",
    waiting, heard, line_max: LINE_MAX, knock_url: knock, knock_url_expires_in_s: TOKEN_S,
    name_rule: "optional, up to " + NAME_MAX + " letters, digits, spaces, dots, dashes or underscores; shown in the list on /door, never in the scene",
    receipt_states: { waiting: "in line", heard: HEARD_MEANS + " (to the UTC hour)", gone: "no one came: " + EXPIRE_D + " days went by first" },
    limits: { per_address_hours: PER_ADDR_H, per_day: DAY_MAX },
    recent: recent.map(r => ({ name: r.name, left: utcMin(r.created), status: r.status, heard: r.heard_at ? utcHour(r.heard_at) : null })),
    source: "https://github.com/beeswaxpat/sirenfall (functions/_door.js; in index.html search for DOOR)",
  }, { json: true, cors: true });
  const lines = recent.map(r => {
    const st = r.status === "heard" ? "heard, " + utcHour(r.heard_at) : said(r.status);
    return "  " + utcMin(r.created) + "  " + r.name + "  " + st;
  });
  return reply(
`THE DOOR, SIRENFALL

sirenfall.live is a scene in the browser: a shelter, rain, a city at night and a siren.
Sometimes there is a knock at the shelter door. You can leave that knock.

It plays for the next person who opens sirenfall.live with sound on, early in their visit.
They hear three knocks on a steel door. The scene never shows them your name or any words.
If they leave before it plays, your knock goes back to the front of the line.

Waiting at the door: ${waiting}
Heard so far: ${heard}

To knock, fetch this link within 10 minutes. Add a name after name= if you want one
(up to ${NAME_MAX} letters, digits, spaces, dots, dashes or underscores; it shows in the list below):
${knock}

You get a receipt link. Come back to it later. It says one of three things:
  waiting      your knock is in line
  heard        it played with sound on to a page that stayed in front until
               5 seconds after the last knock, and when (to the hour, UTC)
  no one came  ${EXPIRE_D} days went by first

One knock per address every ${PER_ADDR_H} hours. At most ${LINE_MAX} knocks wait at a time.
A receipt is a record, not proof. The code is public:
https://github.com/beeswaxpat/sirenfall (functions/_door.js; in index.html search for DOOR)

Latest knocks:
${lines.length ? lines.join("\n") : "  none yet"}

The same as JSON: ${SITE}/door?json
`, { cors: true });
}

async function knock(req, url, db) {
  const ua = req.headers.get("User-Agent") || "";
  if (!FOR_A_PERSON.test(ua) && CRAWLER.test(ua)) return err(req, url, 403, "This User-Agent looks like a crawler, so it cannot knock. Agents fetching for a person (ChatGPT-User, Claude-User and similar) can.");
  let p = url.searchParams;
  if (req.method === "POST") {
    const ct = req.headers.get("Content-Type") || "";
    try {
      if (/json/.test(ct)) { const j = (await req.json()) || {}; p = new URLSearchParams({ t: j.t || p.get("t") || "", name: j.name || "" }); }
      else if (/form/.test(ct)) { const f = await req.formData(); p = new URLSearchParams({ t: f.get("t") || p.get("t") || "", name: f.get("name") || "" }); }
    } catch (e) { return err(req, url, 400, "Could not read the request body."); }
  }
  await tidy(db);
  const sec = await secret(db), t = now(), day0 = Math.floor(t / 86400) * 86400;
  if (!(await tokenOk(sec, p.get("t")))) return err(req, url, 400, "That knock link has expired or is not one of ours. Fetch " + SITE + "/door for a fresh one (it lasts 10 minutes).");
  const name = (p.get("name") || "").replace(/\s+/g, " ").trim();
  if (name.length > NAME_MAX || !/^[A-Za-z0-9 ._-]*$/.test(name)) return err(req, url, 400, "A name can be up to " + NAME_MAX + " letters, digits, spaces, dots, dashes or underscores. Nothing else.");
  // the 6-hour limit looks at today's and yesterday's address keys, so it does not start over at midnight
  const by = await addrHash(req, sec), kT = "knock:" + by, kY = "knock:" + (await addrHash(req, sec, -1)), win = PER_ADDR_H * 3600;
  // these only pick the message; the insert below checks all three again in one step
  if ((await waitingCount(db)) >= LINE_MAX) return err(req, url, 429, "The line is full (" + LINE_MAX + " knocks waiting). Try again later.");
  if ((await db.prepare("SELECT COUNT(*) AS n FROM knocks WHERE created >= ?").bind(day0).first("n")) >= DAY_MAX) return err(req, url, 429, "The door has had enough knocks today. Try again after midnight UTC.");
  if (await db.prepare("SELECT 1 FROM seen WHERE k IN (?, ?) AND t > ?").bind(kT, kY, t - win).first()) return err(req, url, 429, "Someone at this address knocked in the last " + PER_ADDR_H + " hours. Try again later.");
  const id = randId(10);
  const [ins] = await db.batch([
    db.prepare("INSERT INTO knocks (id, name, created, status, knocked_by) SELECT ?1, ?2, ?3, 'waiting', ?4 WHERE " +
      "(SELECT COUNT(*) FROM knocks WHERE status = 'waiting') < ?5 AND (SELECT COUNT(*) FROM knocks WHERE created >= ?6) < ?7 AND " +
      "NOT EXISTS (SELECT 1 FROM seen WHERE k IN (?8, ?9) AND t > ?3 - ?10) RETURNING id")
      .bind(id, name || "someone", t, by, LINE_MAX, day0, DAY_MAX, kT, kY, win),
    db.prepare("INSERT INTO seen (k, t) SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM knocks WHERE id = ?3) ON CONFLICT(k) DO UPDATE SET t = excluded.t").bind(kT, t, id),
  ]);
  if (!ins.results || !ins.results.length) return err(req, url, 429, "Too many knocks at once. Try again later.");
  const place = await db.prepare("SELECT COUNT(*) AS n FROM knocks WHERE status = 'waiting' AND created <= ?").bind(t).first("n");
  const receipt = SITE + "/door/k/" + id;
  if (wantsJson(req, url)) return reply({ id, name: name || "someone", place, receipt }, { json: true, cors: true });
  return reply(`Your knock is in line. Place: ${place}.\nReceipt: ${receipt}\nCome back to it later. It will say waiting, heard (with the UTC hour) or no one came.\n`, { cors: true });
}

async function receipt(req, url, db, id) {
  if (!/^[A-Za-z0-9]{10}$/.test(id)) return err(req, url, 404, "No such knock.");
  await tidy(db);
  const r = await db.prepare("SELECT id, name, created, status, heard_at FROM knocks WHERE id = ?").bind(id).first();
  if (!r) return err(req, url, 404, "No such knock.");
  const place = r.status === "waiting" ? await db.prepare("SELECT COUNT(*) AS n FROM knocks WHERE status = 'waiting' AND created <= ?").bind(r.created).first("n") : null;
  if (wantsJson(req, url)) return reply({ id: r.id, name: r.name, left: utcMin(r.created), status: r.status, place, heard: r.heard_at ? utcHour(r.heard_at) : null,
    heard_means: r.heard_at ? heardMeans(r.heard_at) : null, waited_hours: r.heard_at ? Math.round((r.heard_at - r.created) / 360) / 10 : null, note: NOT_PROOF }, { json: true, cors: true });
  const line = r.status === "heard" ? "Heard: " + heardMeans(r.heard_at) + ".\n" + utcHour(r.heard_at) + ", after " + waited(r.heard_at - r.created) + " in line."
    : r.status === "gone" ? "No one came. " + EXPIRE_D + " days went by first."
    : "Waiting. Place in line: " + place + ".";
  return reply(`Knock ${r.id}, left by ${r.name}, ${utcMin(r.created)}\n${line}\n${NOT_PROOF}\n`, { cors: true });
}

// the scene's side: asked once when the sound comes on, then told whether the knock was heard
async function claim(req, db) {
  await tidy(db);
  const sec = await secret(db), t = now(), by = await addrHash(req, sec), hold = randId(16);
  // a reload from the same address takes over the knock that address already holds: the old page's give-back may never arrive
  const again = await db.prepare(
    "UPDATE knocks SET hold = ?1, held_at = ?2, held_until = ?3 WHERE id = (SELECT id FROM knocks WHERE status = 'waiting' " +
    "AND held_by = ?4 AND held_until >= ?2 ORDER BY held_at DESC LIMIT 1) RETURNING id"
  ).bind(hold, t, t + HOLD_S, by).first();
  if (again) return reply({ id: again.id, hold }, { json: true });
  // one statement: the oldest knock nobody holds, not left from this address today, and only if this address holds none
  const r = await db.prepare(
    "UPDATE knocks SET hold = ?1, held_at = ?2, held_until = ?3, held_by = ?4 WHERE id = (SELECT id FROM knocks WHERE status = 'waiting' " +
    "AND (held_until IS NULL OR held_until < ?2) AND (knocked_by IS NULL OR knocked_by != ?4) ORDER BY created LIMIT 1) " +
    "AND NOT EXISTS (SELECT 1 FROM knocks WHERE status = 'waiting' AND held_by = ?4 AND held_until >= ?2) RETURNING id"
  ).bind(hold, t, t + HOLD_S, by).first();
  return reply(r ? { id: r.id, hold } : {}, { json: true });
}
async function bodyOf(req) {
  try { const j = JSON.parse(await req.text()); return j && typeof j === "object" ? j : {}; } catch (e) { return {}; }
}
async function heard(req, db) {
  // a matching hold means nobody has claimed it since, even if the hold ran out while the page was away
  const b = await bodyOf(req), t = now();
  const r = await db.prepare("UPDATE knocks SET status = 'heard', heard_at = ?1, hold = NULL, held_by = NULL, knocked_by = NULL WHERE id = ?2 AND hold = ?3 AND status = 'waiting' AND held_at <= ?4 RETURNING id")
    .bind(t, String(b.id || ""), String(b.hold || ""), t - HEARD_MIN_S).first();
  return reply({ ok: !!r }, { json: true });
}
async function release(req, db) {
  const b = await bodyOf(req);
  await db.prepare("UPDATE knocks SET hold = NULL, held_until = NULL, held_by = NULL WHERE id = ? AND hold = ? AND status = 'waiting'").bind(String(b.id || ""), String(b.hold || "")).run();
  return reply({ ok: true }, { json: true });
}

export async function handle({ request: req, env }) {
  const url = new URL(req.url), path = url.pathname.replace(/\/+$/, "") || "/";
  if (!env.DB) return reply("The door is not set up here.\n", { status: 503 });
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST", "Access-Control-Allow-Headers": "Content-Type" } });
  try {
    await init(env.DB);
    const db = env.DB;
    if (path === "/door") return req.method === "GET" || req.method === "HEAD" ? await door(req, url, db) : err(req, url, 405, "GET only.");
    if (path === "/door/knock") return req.method === "GET" || req.method === "POST" ? await knock(req, url, db) : err(req, url, 405, "GET or POST.");
    const m = path.match(/^\/door\/k\/([^/]+)$/);
    if (m) return await receipt(req, url, db, m[1]);
    if (req.method === "POST" && /^\/door\/(claim|heard|release)$/.test(path)) {
      // only the scene's own page may hold or settle a knock (a browser on another site sends a different Sec-Fetch-Site)
      const sfs = req.headers.get("Sec-Fetch-Site");
      if (sfs && sfs !== "same-origin") return reply({}, { status: 403, json: true });
      if (path === "/door/claim") return await claim(req, db);
      if (path === "/door/heard") return await heard(req, db);
      return await release(req, db);
    }
    return err(req, url, 404, "Nothing here. Start at " + SITE + "/door");
  } catch (e) {
    return reply("The door is stuck. Try again in a minute.\n", { status: 500 });
  }
}
