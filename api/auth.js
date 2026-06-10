// api/auth.js — Google OAuth handler (Vercel Serverless Function)
// Env vars needed in Vercel dashboard:
//   GOOGLE_CLIENT_ID      — from Google Cloud Console
//   GOOGLE_CLIENT_SECRET  — from Google Cloud Console
//   SESSION_SECRET        — any long random string (used to sign tokens)
//   ALLOWED_DOMAIN        — astrotalk.com

const crypto = require('crypto');

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SESSION_SECRET,
  ALLOWED_DOMAIN = 'astrotalk.com',
} = process.env;

// ── Derive base URL from request ──────────────────────────────────────────
function getBaseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host  = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}

// ── Simple signed token (HMAC-SHA256, no JWT lib needed) ──────────────────
function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  try {
    const [data, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ── Cookie helpers ────────────────────────────────────────────────────────
function setCookie(res, name, value, maxAge = 60 * 60 * 8) {
  // 8 hour session
  res.setHeader('Set-Cookie',
    `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`
  );
}

function clearCookie(res, name) {
  res.setHeader('Set-Cookie',
    `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  );
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || '';
  const match   = cookies.split(';').find(c => c.trim().startsWith(name + '='));
  return match ? match.trim().slice(name.length + 1) : null;
}

// ── Main handler ──────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  const { searchParams } = new URL(req.url, getBaseUrl(req));
  const action = searchParams.get('action');

  // ── /api/auth?action=login → redirect to Google ──────────────────────
  if (action === 'login') {
    if (!GOOGLE_CLIENT_ID) {
      return res.status(500).send('GOOGLE_CLIENT_ID env var not set. See setup instructions.');
    }
    const base     = getBaseUrl(req);
    const redirect = encodeURIComponent(`${base}/api/auth?action=callback`);
    const state    = crypto.randomBytes(16).toString('hex');
    setCookie(res, 'oauth_state', state, 600); // 10 min

    const url = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${GOOGLE_CLIENT_ID}` +
      `&redirect_uri=${redirect}` +
      `&response_type=code` +
      `&scope=openid%20email%20profile` +
      `&access_type=online` +
      `&prompt=select_account` +
      `&state=${state}` +
      `&hd=${ALLOWED_DOMAIN}`;       // ← restricts Google picker to org domain

    res.writeHead(302, { Location: url });
    return res.end();
  }

  // ── /api/auth?action=callback → exchange code for token ─────────────
  if (action === 'callback') {
    const code  = searchParams.get('code');
    const state = searchParams.get('state');
    const error = searchParams.get('error');

    if (error) {
      res.writeHead(302, { Location: `/?error=${encodeURIComponent(error)}` });
      return res.end();
    }

    // CSRF check
    const savedState = getCookie(req, 'oauth_state');
    if (!state || state !== savedState) {
      res.writeHead(302, { Location: '/?error=invalid_state' });
      return res.end();
    }
    clearCookie(res, 'oauth_state');

    // Exchange code for tokens
    const base     = getBaseUrl(req);
    const redirect = `${base}/api/auth?action=callback`;

    let tokenRes;
    try {
      tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id:     GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri:  redirect,
          grant_type:    'authorization_code',
        }),
      });
    } catch(e) {
      res.writeHead(302, { Location: '/?error=token_fetch_failed' });
      return res.end();
    }

    const tokens = await tokenRes.json();
    if (!tokens.id_token) {
      res.writeHead(302, { Location: '/?error=no_id_token' });
      return res.end();
    }

    // Decode id_token (we trust Google's signature via HTTPS — no lib needed)
    let userInfo;
    try {
      const payload = tokens.id_token.split('.')[1];
      userInfo = JSON.parse(Buffer.from(payload, 'base64url').toString());
    } catch {
      res.writeHead(302, { Location: '/?error=invalid_token' });
      return res.end();
    }

    const email = (userInfo.email || '').toLowerCase();

    // ── Domain check ──────────────────────────────────────────────────
    if (!email.endsWith('@' + ALLOWED_DOMAIN)) {
      res.writeHead(302, {
        Location: `/?error=unauthorized_domain&error_description=${encodeURIComponent(
          `Only @${ALLOWED_DOMAIN} accounts are allowed. You signed in as ${email}.`
        )}`
      });
      return res.end();
    }

    // ── Issue session cookie ──────────────────────────────────────────
    const sessionPayload = {
      email,
      name:    userInfo.name    || '',
      picture: userInfo.picture || '',
      exp:     Date.now() + 8 * 60 * 60 * 1000, // 8 hours
    };
    const token = signToken(sessionPayload);
    setCookie(res, 'inv_session', token, 60 * 60 * 8);

    res.writeHead(302, { Location: '/' });
    return res.end();
  }

  // ── /api/auth?action=session → return current user ───────────────────
  if (action === 'session') {
    const token = getCookie(req, 'inv_session');
    if (!token) {
      return res.status(401).json({ error: 'no session' });
    }
    const user = verifyToken(token);
    if (!user) {
      clearCookie(res, 'inv_session');
      return res.status(401).json({ error: 'invalid or expired session' });
    }
    res.setHeader('Content-Type', 'application/json');
    return res.status(200).json({ email: user.email, name: user.name, picture: user.picture });
  }

  // ── /api/auth?action=logout ───────────────────────────────────────────
  if (action === 'logout') {
    clearCookie(res, 'inv_session');
    return res.status(200).json({ ok: true });
  }

  return res.status(400).json({ error: 'unknown action' });
};
