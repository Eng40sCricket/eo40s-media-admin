/* ============================================================
   England Over 40s Cricket — Media Admin (backend)
   ------------------------------------------------------------
   Netlify serverless function — a deliberately narrow GitHub proxy.

   The GitHub token is held HERE, server-side, as the environment
   variable GITHUB_TOKEN, and is never sent to the browser. The
   admin tool sends only the PIN, which this function checks
   against the ADMIN_PIN environment variable.

   PATH RESTRICTION — the important safety property.
   This function will only ever read or write:
     - media/index.html
     - assets/img/photos/<filename>   (one path segment, no slashes)
   in the repository Eng40sCricket/eng40s-website. Every other path
   is refused with 403, so even with the PIN the tool cannot be
   used to touch the rest of the website.

   Required environment variables
   (Netlify -> Site configuration -> Environment variables):

     GITHUB_TOKEN  Fine-grained Personal Access Token, scoped to
                   the single repository Eng40sCricket/eng40s-website,
                   with Repository permission "Contents: Read and write".

     ADMIN_PIN     The admin PIN for unlocking the tool.

   Actions handled (POST, JSON body):

     { action: "ping", pin }
        -> { ok: true }                  (verifies the PIN only)

     { action: "getFile", pin, path }
        -> { sha, content }              (content is base64)

     { action: "putFile", pin, path, contentBase64, message, sha }
        sha is optional — if omitted, the function looks the file
        up and reuses its sha so an existing file is updated.
        -> { ok: true, sha }
   ============================================================ */

const GH_API = 'https://api.github.com';
const OWNER  = 'Eng40sCricket';
const REPO   = 'eng40s-website';
const BRANCH = 'main';

function json(statusCode, obj) {
  return {
    statusCode: statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj)
  };
}

/* The ONLY paths this tool is permitted to read or write. */
function isAllowedPath(path) {
  if (typeof path !== 'string' || path.indexOf('..') !== -1) return false;
  if (path === 'media/index.html') return true;
  /* assets/img/photos/<filename> — a single segment, safe characters */
  return /^assets\/img\/photos\/[A-Za-z0-9._-]+$/.test(path);
}

function ghHeaders(token, extra) {
  const h = {
    'Authorization': 'Bearer ' + token,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'eo40s-media-admin'
  };
  if (extra) Object.keys(extra).forEach(function (k) { h[k] = extra[k]; });
  return h;
}

/* Returns the GitHub contents object, or null on 404. */
async function ghGet(token, path) {
  const url = GH_API + '/repos/' + OWNER + '/' + REPO + '/contents/' + path + '?ref=' + BRANCH;
  const res = await fetch(url, { headers: ghHeaders(token) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('GitHub read failed (' + res.status + ').');
  return res.json();
}

async function ghPut(token, path, contentBase64, message, sha) {
  const body = { message: message, content: contentBase64, branch: BRANCH };
  if (sha) body.sha = sha;
  const res = await fetch(GH_API + '/repos/' + OWNER + '/' + REPO + '/contents/' + path, {
    method: 'PUT',
    headers: ghHeaders(token, { 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    let detail = '';
    try { const e = await res.json(); detail = e.message || ''; } catch (e) {}
    throw new Error(detail || ('GitHub write failed (' + res.status + ').'));
  }
  return res.json();
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return json(405, { error: 'Method not allowed.' });
  }

  const TOKEN = process.env.GITHUB_TOKEN;
  const PIN   = process.env.ADMIN_PIN;
  if (!TOKEN || !PIN) {
    return json(500, { error: 'Server not configured: GITHUB_TOKEN and ADMIN_PIN must both be set.' });
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return json(400, { error: 'Invalid request body.' });
  }

  /* PIN check — performed server-side, for every action. */
  if (!body.pin || body.pin !== PIN) {
    return json(401, { error: 'Incorrect PIN.' });
  }

  try {
    /* ---- PING: verify the PIN only (used by the login screen) ---- */
    if (body.action === 'ping') {
      return json(200, { ok: true });
    }

    /* ---- GET FILE ---- */
    if (body.action === 'getFile') {
      if (!isAllowedPath(body.path)) {
        return json(403, { error: 'That file is outside this tool’s permitted area.' });
      }
      const data = await ghGet(TOKEN, body.path);
      if (!data) return json(404, { error: 'File not found in the repository.' });
      return json(200, { sha: data.sha, content: (data.content || '').replace(/\n/g, '') });
    }

    /* ---- PUT FILE ---- */
    if (body.action === 'putFile') {
      if (!isAllowedPath(body.path)) {
        return json(403, { error: 'That file is outside this tool’s permitted area.' });
      }
      if (typeof body.contentBase64 !== 'string' || !body.contentBase64) {
        return json(400, { error: 'No file content was supplied.' });
      }
      /* If no sha was given, look the file up so an existing file
         is updated rather than rejected. */
      let sha = body.sha || null;
      if (!sha) {
        const existing = await ghGet(TOKEN, body.path);
        if (existing) sha = existing.sha;
      }
      const result = await ghPut(
        TOKEN, body.path, body.contentBase64,
        body.message || 'Media admin update', sha
      );
      return json(200, { ok: true, sha: (result && result.content && result.content.sha) || null });
    }

    return json(400, { error: 'Unknown action.' });
  } catch (e) {
    return json(502, { error: (e && e.message) || 'Upstream error contacting GitHub.' });
  }
};
