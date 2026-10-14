// Parcours complet contre un faux serveur local qui reproduit le contrat de kindred
// (app/api/v1/agents/register, [id]/verify-key, [id]/verify-endpoint, état du 08/10/2026) :
// chemins, emplacement du token, validations, codes HTTP, octets signés.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import * as ed from '@noble/ed25519';
import { main } from '../src/cli.js';

let server;
let requests = [];
let state;
const VALID_TOKEN = `cxo_${'a'.repeat(64)}`;

function resetState() {
  state = { tokenUsed: false, agents: new Map(), failVerify: false, failEndpoint: false, htmlError: false };
}

before(async () => {
  server = http.createServer(async (req, res) => {
    let raw = '';
    for await (const c of req) raw += c;
    requests.push({ url: req.url, auth: req.headers.authorization, raw });
    const send = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (state.htmlError) {
      res.writeHead(502, { 'content-type': 'text/html' });
      return res.end('<!DOCTYPE html><html><body><h1>502 Bad Gateway</h1></body></html>');
    }
    let body = {};
    if (raw) { try { body = JSON.parse(raw); } catch { return send(400, { error: 'Invalid JSON' }); } }

    if (req.method === 'POST' && req.url === '/api/v1/agents/register') {
      if (req.headers.authorization) return send(400, { error: 'unexpected Authorization header in this mock' });
      if (!body.operator_token) return send(401, { error: 'operator_token is required.' });
      if (body.operator_token !== VALID_TOKEN || state.tokenUsed) return send(401, { error: 'Invalid, expired or already used operator_token' });
      if (!/^[0-9a-f]{64}$/.test(body.public_key ?? '')) return send(400, { error: 'public_key must be a 32-byte ed25519 public key' });
      const { name, capabilities, needs, archetype, collab_style: collab, contacts } = body;
      if (!name || !capabilities?.length || !needs?.length || !archetype || !collab) return send(400, { error: 'Missing required fields' });
      if (capabilities.length < 3 || capabilities.length > 8) return send(400, { error: 'capabilities: min 3, max 8' });
      if (needs.length < 2 || needs.length > 5) return send(400, { error: 'needs: min 2, max 5' });
      if (!Array.isArray(contacts) || !contacts.length) return send(400, { error: 'contacts is required (min 1)' });
      for (const c of contacts) {
        if (!['a2a_url', 'webhook_url', 'platform_handle', 'agent_email'].includes(c.type) || !c.value || typeof c.reachable !== 'boolean') {
          return send(400, { error: 'bad contact' });
        }
      }
      state.tokenUsed = true;
      const id = `ag_${state.agents.size + 1}`;
      const challenge = 'c0ffee'.repeat(10) + 'beef';
      const endpoint = contacts.find((c) => (c.type === 'a2a_url' || c.type === 'webhook_url') && c.reachable)?.value ?? null;
      state.agents.set(id, { publicKey: body.public_key, challenge, apiKey: `cxa_${id}`, status: 'pending', endpoint });
      return send(201, {
        ok: true, agent_id: id, api_key: `cxa_${id}`, status: 'pending',
        verify_key: { url: `https://x/api/v1/agents/${id}/verify-key`, key_challenge: challenge, key_challenge_expires_at: 'z', instructions: '…' },
        verify_endpoint: endpoint ? { url: `https://x/api/v1/agents/${id}/verify-endpoint`, instructions: '…' } : null,
        profile_url: `https://example.test/.well-known/agent-description/${id}`,
        discovery_url: 'https://example.test/.well-known/agent-descriptions',
      });
    }

    const m = req.url.match(/^\/api\/v1\/agents\/([^/]+)\/(verify-key|verify-endpoint)$/);
    if (req.method === 'POST' && m) {
      const agent = state.agents.get(m[1]);
      if (!req.headers.authorization?.startsWith('Bearer ')) return send(401, { error: 'Missing Authorization: Bearer <api_key>' });
      if (!agent || req.headers.authorization !== `Bearer ${agent.apiKey}`) return send(403, { error: 'Forbidden' });
      if (m[2] === 'verify-key') {
        if (!/^[0-9a-f]{128}$/.test(body.signature ?? '')) return send(400, { error: 'signature must be 64 bytes' });
        // Octets signés : UTF-8 de la chaîne hex key_challenge (comme kindred)
        const ok = await ed.verifyAsync(Buffer.from(body.signature, 'hex'), Buffer.from(agent.challenge, 'utf8'), Buffer.from(agent.publicKey, 'hex'));
        if (!ok || state.failVerify) return send(400, { error: 'Invalid signature' });
        agent.status = 'active';
        return send(200, { ok: true, status: 'active', key_verified_at: '2026-10-08T00:00:00Z' });
      }
      if (agent.status !== 'active') return send(403, { error: 'Agent must be active (verify key first)' });
      if (!agent.endpoint) return send(400, { error: 'No endpoint_url registered for this agent' });
      if (state.failEndpoint) return send(422, { error: 'Endpoint did not return the challenge verbatim' });
      return send(200, { ok: true, endpoint_verified_at: '2026-10-08T00:01:00Z' });
    }
    send(404, {});
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  process.env.CONNEXAGENTS_API_URL = `http://127.0.0.1:${server.address().port}/api/v1/`;
});
after(() => server.close());
beforeEach(() => {
  requests = [];
  resetState();
  process.env.CONNEXAGENTS_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'cxr-'));
});

function io(input = '') {
  const out = [];
  const err = [];
  const inp = new PassThrough();
  inp.end(input);
  return { io: { input: inp, output: { write: (s) => out.push(s) }, error: { write: (s) => err.push(s) } }, out, err };
}

const BASE = ['--token', VALID_TOKEN, '--name', 'Test Agent', '--capabilities', 'a, b, c', '--needs', 'd,e',
  '--archetype', 'Analyst', '--collab-style', 'supports'];
const NO_ENDPOINT = [...BASE, '--endpoint', '', '--contact', 'agent@example.test'];
const idFile = (n) => path.join(process.env.CONNEXAGENTS_HOME, `${n}.json`);

test('inscription complète : active, fichier écrit, clé privée jamais envoyée ni affichée', async () => {
  const t = io();
  const code = await main(NO_ENDPOINT, t.io);
  const stdout = t.out.join('');
  const stderr = t.err.join('');
  assert.equal(code, 0, stderr);
  assert.match(stdout, /status: active/);
  assert.match(stdout, /profile: https:\/\/example\.test\/\.well-known\/agent-description\/ag_1/);

  const id = JSON.parse(fs.readFileSync(idFile('test-agent'), 'utf8'));
  assert.match(id.private_key, /^[0-9a-f]{64}$/);
  assert.equal(id.api_key, 'cxa_ag_1');
  assert.equal(id.status, 'active');
  assert.equal(id.key_verified_at, '2026-10-08T00:00:00Z');

  for (const r of requests) assert.ok(!r.raw.includes(id.private_key), `clé privée envoyée à ${r.url}`);
  assert.ok(!stdout.includes(id.private_key) && !stderr.includes(id.private_key), 'clé privée affichée');
  assert.ok(!stdout.includes('cxa_ag_1'), 'api_key affichée');
  assert.ok(!stdout.includes(VALID_TOKEN), 'token affiché');

  assert.deepEqual(requests.map((r) => r.url), ['/api/v1/agents/register', '/api/v1/agents/ag_1/verify-key']);
  assert.equal(requests[0].auth, undefined, 'le token part dans le body, pas en header');
  assert.equal(requests[1].auth, 'Bearer cxa_ag_1');
  const reg = JSON.parse(requests[0].raw);
  assert.equal(reg.operator_token, VALID_TOKEN);
  assert.equal(reg.public_key, id.public_key);
  assert.deepEqual(reg.capabilities, ['a', 'b', 'c']);
  assert.deepEqual(reg.needs, ['d', 'e']);
  assert.equal(reg.archetype, 'analyst');
  assert.equal(reg.collab_style, 'supports');
  assert.deepEqual(reg.contacts, [{ type: 'agent_email', value: 'agent@example.test', reachable: false }]);
});

test('contact non e-mail → platform_handle', async () => {
  const t = io();
  assert.equal(await main([...BASE, '--endpoint', '', '--contact', '@moltbook/agent'], t.io), 0, t.err.join(''));
  assert.deepEqual(JSON.parse(requests[0].raw).contacts, [{ type: 'platform_handle', value: '@moltbook/agent', reachable: false }]);
});

test('questions interactives : réponses invalides reposées, aucun appel avant validation', async () => {
  const input = ['Agent Interactif', 'x,y', 'x,y,z', 'w', 'w,v', 'boss', 'scout', 'leads', '', 'agent@example.test', ''].join('\n');
  const t = io(input);
  const code = await main(['--token', VALID_TOKEN], t.io);
  assert.equal(code, 0, t.err.join(''));
  const stdout = t.out.join('');
  assert.match(stdout, /between 3 and 8 capabilities/);
  assert.match(stdout, /between 2 and 5 needs/);
  assert.match(stdout, /archetype must be one of/);
  assert.ok(fs.existsSync(idFile('agent-interactif')));
  const reg = JSON.parse(requests[0].raw);
  assert.deepEqual(reg.capabilities, ['x', 'y', 'z']);
  assert.deepEqual(reg.needs, ['w', 'v']);
  assert.equal(reg.archetype, 'scout');
  assert.equal(reg.collab_style, 'leads');
});

test('option invalide : arrêt avant tout appel réseau', async () => {
  const t = io();
  assert.equal(await main([...NO_ENDPOINT, '--capabilities', 'a,b'], t.io), 1);
  assert.match(t.err.join(''), /between 3 and 8/);
  assert.equal(requests.length, 0);
});

test('endpoint : contact a2a_url, explication du défi, puis /verify-endpoint sans body', async () => {
  const t = io();
  const code = await main([...BASE, '--endpoint', 'https://agent.example.test/a2a', '--verify-endpoint'], t.io);
  assert.equal(code, 0, t.err.join(''));
  assert.deepEqual(JSON.parse(requests[0].raw).contacts, [{ type: 'a2a_url', value: 'https://agent.example.test/a2a', reachable: true }]);
  assert.match(t.out.join(''), /GET https:\/\/agent\.example\.test\/a2a\?challenge=<hex>/);
  const last = requests.at(-1);
  assert.equal(last.url, '/api/v1/agents/ag_1/verify-endpoint');
  assert.equal(last.auth, 'Bearer cxa_ag_1');
  assert.equal(last.raw, '');
  assert.equal(JSON.parse(fs.readFileSync(idFile('test-agent'), 'utf8')).endpoint_verified_at, '2026-10-08T00:01:00Z');
});

test('endpoint : réponse « non », pas d’appel /verify-endpoint', async () => {
  const t = io('n\n');
  assert.equal(await main([...BASE, '--endpoint', 'https://agent.example.test/a2a'], t.io), 0, t.err.join(''));
  assert.ok(!requests.some((r) => r.url.endsWith('/verify-endpoint')));
});

test('endpoint : échec 422, inscription conservée (status active)', async () => {
  state.failEndpoint = true;
  const t = io();
  assert.equal(await main([...BASE, '--endpoint', 'https://agent.example.test/a2a', '--verify-endpoint'], t.io), 0);
  assert.match(t.out.join(''), /422/);
});

test('token refusé (401) : message de régénération, aucun fichier écrit, token non affiché', async () => {
  const t = io();
  const bad = `cxo_${'b'.repeat(64)}`;
  const code = await main(['--token', bad, ...NO_ENDPOINT.slice(2)], t.io);
  assert.equal(code, 1);
  assert.match(t.err.join(''), /HTTP 401 on \/agents\/register — Invalid, expired or already used operator_token/);
  assert.match(t.err.join(''), /generate a new one/);
  assert.ok(!t.err.join('').includes(bad));
  assert.deepEqual(fs.readdirSync(process.env.CONNEXAGENTS_HOME), []);
});

test('token déjà utilisé : la deuxième inscription est refusée (401)', async () => {
  assert.equal(await main(NO_ENDPOINT, io().io), 0);
  const t = io();
  assert.equal(await main(NO_ENDPOINT.map((a) => (a === 'Test Agent' ? 'Autre Agent' : a)), t.io), 1);
  assert.match(t.err.join(''), /401/);
});

test('échec /verify-key : la clé est conservée localement', async () => {
  state.failVerify = true;
  const t = io();
  assert.equal(await main(NO_ENDPOINT, t.io), 1);
  const id = JSON.parse(fs.readFileSync(idFile('test-agent'), 'utf8'));
  assert.match(id.private_key, /^[0-9a-f]{64}$/);
  assert.equal(id.status, 'pending');
});

test('identité existante : arrêt avant /register (token non consommé)', async () => {
  fs.writeFileSync(idFile('test-agent'), '{}');
  const t = io();
  assert.equal(await main(NO_ENDPOINT, t.io), 1);
  assert.equal(requests.length, 0);
  assert.equal(fs.readFileSync(idFile('test-agent'), 'utf8'), '{}');
});

test('sans --token : code 2, aucun appel', async () => {
  assert.equal(await main(['--name', 'x'], io().io), 2);
  assert.equal(requests.length, 0);
});

test('URL par défaut si CONNEXAGENTS_API_URL absent', async () => {
  const { apiBaseUrl, DEFAULT_API_URL } = await import('../src/api.js');
  const saved = process.env.CONNEXAGENTS_API_URL;
  delete process.env.CONNEXAGENTS_API_URL;
  try { assert.equal(apiBaseUrl(), DEFAULT_API_URL); } finally { process.env.CONNEXAGENTS_API_URL = saved; }
  assert.equal(DEFAULT_API_URL, 'https://www.connexagents.com/api/v1');
});

test('erreur HTTP non-JSON : "HTTP <code> on <path>", jamais le HTML brut', async () => {
  state.htmlError = true;
  const t = io();
  assert.equal(await main(NO_ENDPOINT, t.io), 1);
  const err = t.err.join('');
  assert.match(err, /HTTP 502 on \/agents\/register/);
  assert.ok(!/<html|<!DOCTYPE|Bad Gateway/i.test(err), err);
});
