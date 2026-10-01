const http = require('http');
const fs = require('fs');

const ABS_BASE_URL = process.env.ABS_BASE_URL || 'http://192.168.9.151:13378';
const TOKEN_FILE = process.env.TOKEN_FILE || '/app/abs.token';
const PORT = Number(process.env.PORT || 7778);
const SESSIONS_LIMIT = Number(process.env.SESSIONS_LIMIT || 20);
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_SECONDS || 30) * 1000;
const ITEM_CACHE_TTL_MS = Number(process.env.ITEM_CACHE_TTL_SECONDS || 3600) * 1000;

const TOKEN = (process.env.ABS_TOKEN || fs.readFileSync(TOKEN_FILE, 'utf8')).trim(); // env first, file as fallback
const INDEX_HTML = fs.readFileSync(process.env.INDEX_FILE || '/app/index.html', 'utf8');
const WIDGET_HTML = fs.readFileSync(process.env.WIDGET_FILE || '/app/widget.html', 'utf8');

const PLAY_METHODS = { 0: 'direct play', 1: 'direct stream', 2: 'transcode' };

let sessionsCache = { data: null, at: 0 };
const itemCache = new Map(); // libraryItemId -> { chapters, at }

async function absFetch(path) {
  const res = await fetch(`${ABS_BASE_URL}${path}`, {
    headers: { Authorization: `Bearer ${TOKEN}` }
  });
  if (!res.ok) throw new Error(`ABS ${path} -> HTTP ${res.status}`);
  return res.json();
}

async function getChapters(libraryItemId) {
  const cached = itemCache.get(libraryItemId);
  if (cached && Date.now() - cached.at < ITEM_CACHE_TTL_MS) return cached.chapters;
  const item = await absFetch(`/api/items/${libraryItemId}?expanded=1`);
  const chapters = item.media?.chapters || [];
  itemCache.set(libraryItemId, { chapters, at: Date.now() });
  return chapters;
}

function findChapter(chapters, currentTime) {
  const ch = chapters.find(c => currentTime >= c.start && currentTime < c.end);
  return ch ? { number: ch.id + 1, title: ch.title } : null;
}

async function buildSessions() {
  const raw = await absFetch(`/api/me/listening-sessions?itemsPerPage=${SESSIONS_LIMIT}&page=0`);
  const sessions = await Promise.all((raw.sessions || []).map(async s => {
    const chapters = await getChapters(s.libraryItemId).catch(() => []);
    return {
      id: s.id,
      date: s.date,
      dayOfWeek: s.dayOfWeek,
      startedAt: new Date(s.startedAt).toISOString(),
      updatedAt: new Date(s.updatedAt).toISOString(),
      book: {
        title: s.displayTitle,
        authors: (s.mediaMetadata?.authors || []).map(a => a.name),
        libraryItemId: s.libraryItemId
      },
      chapter: findChapter(chapters, s.currentTime),
      progress: {
        currentTime: Math.round(s.currentTime),
        duration: Math.round(s.duration),
        percent: Math.round((s.currentTime / s.duration) * 10000) / 100,
        timeListeningThisSession: Math.round(s.timeListening)
      },
      device: {
        app: s.deviceInfo?.clientName || s.mediaPlayer,
        os: [s.deviceInfo?.osName, s.deviceInfo?.osVersion].filter(Boolean).join(' '),
        browser: [s.deviceInfo?.browserName, s.deviceInfo?.browserVersion].filter(Boolean).join(' '),
        ip: s.deviceInfo?.ipAddress || null,
        playMethod: PLAY_METHODS[s.playMethod] ?? 'unknown'
      }
    };
  }));
  return { count: sessions.length, sessions };
}

async function getSessionsCached() {
  if (sessionsCache.data && Date.now() - sessionsCache.at < CACHE_TTL_MS) {
    return { ...sessionsCache.data, cacheAgeSeconds: Math.round((Date.now() - sessionsCache.at) / 1000) };
  }
  const built = await buildSessions();
  sessionsCache = { data: built, at: Date.now() };
  return { ...built, cacheAgeSeconds: 0 };
}

const server = http.createServer(async (req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(INDEX_HTML);
  }
  if (req.url === '/widget') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(WIDGET_HTML);
  }
  if (req.url === '/api') {
    try {
      const body = await getSessionsCached();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ generatedAt: new Date().toISOString(), ...body }, null, 2));
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: e.message }, null, 2));
    }
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
});

server.listen(PORT, () => console.log(`abs-session-api listening on :${PORT}`));
