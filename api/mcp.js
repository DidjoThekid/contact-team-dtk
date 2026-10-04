// Serveur MCP "Team DTK" : rappel téléphonique (Zadarma)
// Compatible Claude (connecteur personnalisé) et ChatGPT (Apps SDK). Aucune dépendance.
const crypto = require('crypto');

const SERVER_INFO = { name: 'team-dtk-contact', version: '1.0.0' };
const DEFAULT_PROTOCOL = '2025-06-18';
const env = (k, d = '') => process.env[k] || d;

/* ---------- Limites (en mémoire : valables par instance serverless, "au mieux") ---------- */
const hits = new Map();
function allow(key, max, windowMs) {
  const now = Date.now();
  const list = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (list.length >= max) { hits.set(key, list); return false; }
  list.push(now); hits.set(key, list); return true;
}
const HOUR = 3600e3, DAY = 24 * HOUR;

/* ---------- Horaires : désactivés (rappels 24h/24) ---------- */
function openNow() { return true; }
const HOURS_TEXT = '24h/24, 7j/7';

/* ---------- Numéros de téléphone ---------- */
function normalizePhone(raw) {
  let s = String(raw || '').replace(/[\s().-]/g, '');
  if (s.startsWith('00')) s = '+' + s.slice(2);
  if (/^0[1-9]\d{8}$/.test(s)) s = '+33' + s.slice(1); // numéro français saisi à l'ancienne
  return s;
}
function checkPhone(e164) {
if (!/^\+[1-9]\d{7,14}$/.test(e164)) return 'Numéro invalide. Utilisez le format international, par exemple +33612345678.';
  const prefixes = env('ALLOWED_PREFIXES', '+33').split(',').map((x) => x.trim());
  if (!prefixes.some((p) => e164.startsWith(p))) return 'Ce service rappelle uniquement les numéros de : ' + prefixes.join(', ') + '.';
  if (e164.startsWith('+33') && !/^\+33[1-79]\d{8}$/.test(e164)) return 'Numéro français non pris en charge (numéros spéciaux exclus).';
  return null;
}

/* ---------- API Zadarma (signature : base64(hex(HMAC-SHA1(méthode + params + md5(params))))) ---------- */
async function zadarma(method, params) {
  const key = env('ZADARMA_KEY'), secret = env('ZADARMA_SECRET');
  if (!key || !secret) throw new Error('Clés Zadarma manquantes côté serveur.');
  const sorted = Object.keys(params).sort().reduce((o, k) => ((o[k] = params[k]), o), {});
  const qs = new URLSearchParams(sorted).toString();
  const data = method + qs + crypto.createHash('md5').update(qs).digest('hex');
  const sig = Buffer.from(crypto.createHmac('sha1', secret).update(data).digest('hex')).toString('base64');
  const r = await fetch('https://api.zadarma.com' + method + '?' + qs, { headers: { Authorization: key + ':' + sig } });
  return r.json();
}

/* ---------- Outils ---------- */
async function demanderRappel(args) {
  const phone = normalizePhone(args.numero);
  const bad = checkPhone(phone);
  if (bad) return { error: bad };
  if (!openNow()) return { error: 'L\'équipe n\'est pas disponible maintenant. Horaires : ' + HOURS_TEXT + '. Invitez la personne à réessayer pendant les horaires d\'ouverture.' };
  if (!allow('call:' + phone, 2, HOUR)) return { error: 'Trop de demandes pour ce numéro. Réessayez dans une heure.' };
  if (!allow('call:global', parseInt(env('MAX_CALLS_PER_DAY', '30'), 10), DAY)) return { error: 'Limite quotidienne de rappels atteinte. Réessayez demain.' };
  const out = await zadarma('/v1/request/callback/', { from: env('ZADARMA_SIP', '518175'), to: phone.slice(1) });
  if (out.status !== 'success') return { error: 'Le rappel a échoué : ' + (out.message || 'erreur Zadarma') };
  return { ok: 'Rappel lancé. L\'équipe Team DTK décroche d\'abord, puis le ' + phone + ' sonne dans quelques instants.' };
}

const TOOLS = [
  {
    name: 'demander_rappel',
    description: 'Fait rappeler un visiteur par téléphone par la Team DTK. Confirmez toujours le numéro avec la personne avant l\'appel. Disponible : ' + HOURS_TEXT + '. Numéros français uniquement.',
inputSchema: { type: 'object', properties: { numero: { type: 'string', description: 'Numéro à rappeler, format international (+33612345678) ou français (0612345678).' } }, required: ['numero'], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    run: demanderRappel,
  },
];

/* ---------- Protocole MCP (JSON-RPC sur HTTP, sans état) ---------- */
async function handle(msg) {
  const { id, method, params } = msg || {};
  const ok = (result) => ({ jsonrpc: '2.0', id, result });
  const ko = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
  if (id === undefined) return null; // notification
  switch (method) {
    case 'initialize':
      return ok({ protocolVersion: (params && params.protocolVersion) || DEFAULT_PROTOCOL, capabilities: { tools: {} }, serverInfo: SERVER_INFO });
    case 'ping':
      return ok({});
    case 'tools/list':
      return ok({ tools: TOOLS.map(({ run, ...t }) => t) });
    case 'tools/call': {
      const tool = TOOLS.find((t) => t.name === (params && params.name));
      if (!tool) return ko(-32602, 'Outil inconnu');
      try {
        const out = await tool.run((params && params.arguments) || {});
        return ok({ content: [{ type: 'text', text: out.ok || out.error }], isError: !!out.error });
      } catch (e) {
        return ok({ content: [{ type: 'text', text: 'Erreur du serveur. Réessayez plus tard.' }], isError: true });
      }
    }
    default:
      return ko(-32601, 'Méthode inconnue');
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type, mcp-session-id, mcp-protocol-version, authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST, OPTIONS'); return res.status(405).json({ error: 'Utilisez POST' }); }
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = null; } }
  if (!body) return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'JSON invalide' } });
  if (Array.isArray(body)) {
    const out = (await Promise.all(body.map(handle))).filter(Boolean);
    return out.length ? res.status(200).json(out) : res.status(202).end();
  }
  const out = await handle(body);
  return out ? res.status(200).json(out) : res.status(202).end();
};
