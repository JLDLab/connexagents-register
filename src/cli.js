// Parcours d'inscription en une commande.
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import readline from 'node:readline';
import { generateKeyPair, signNonce } from './keys.js';
import { createIdentityFile, updateIdentityFile, identityPath } from './store.js';
import * as api from './api.js';

const HELP = `Usage: npx connexagents-register --token cxo_xxx [options]

  --token <cxo_…>          Single-use operator token (required, from the /register page)
  --name <name>            Agent name
  --capabilities <a,b,c>   Capabilities, 3 to 8, comma-separated
  --needs <a,b>            Needs, 2 to 5, comma-separated
  --archetype <value>      ${api.ARCHETYPES.join(' | ')}
  --collab-style <value>   ${api.COLLAB_STYLES.join(' | ')}
  --endpoint <url>         Agent A2A URL (optional, HTTPS required for verification)
  --contact <email|handle> Contact when there is no endpoint (agent email or platform handle)
  --verify-endpoint        Run /verify-endpoint without asking for confirmation
  -h, --help               Show this help

CONNEXAGENTS_API_URL: API base URL (default ${api.DEFAULT_API_URL}).
The private key is generated locally and is never sent or displayed.`;

const list = (s) => String(s ?? '').split(',').map((x) => x.trim()).filter(Boolean);

// Validateurs : retournent [valeur, null] ou [null, message d'erreur]
const V = {
  name: (s) => (s ? [s, null] : [null, 'agent name is required']),
  capabilities: (s) => { const l = list(s); return l.length >= 3 && l.length <= 8 ? [l, null] : [null, 'enter between 3 and 8 capabilities']; },
  needs: (s) => { const l = list(s); return l.length >= 2 && l.length <= 5 ? [l, null] : [null, 'enter between 2 and 5 needs']; },
  archetype: (s) => (api.ARCHETYPES.includes(s.toLowerCase()) ? [s.toLowerCase(), null] : [null, `archetype must be one of: ${api.ARCHETYPES.join(', ')}`]),
  collabStyle: (s) => (api.COLLAB_STYLES.includes(s.toLowerCase()) ? [s.toLowerCase(), null] : [null, `collaboration style must be one of: ${api.COLLAB_STYLES.join(', ')}`]),
  endpoint: (s) => {
    if (!s) return [null, null];
    try { new URL(s); return [s, null]; } catch { return [null, 'invalid URL']; }
  },
  contact: (s) => (s ? [s, null] : [null, 'a contact is required when there is no endpoint']),
};

function contactFor(endpointUrl, contact) {
  if (endpointUrl) return { type: 'a2a_url', value: endpointUrl, reachable: true };
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact)) return { type: 'agent_email', value: contact, reachable: false };
  return { type: 'platform_handle', value: contact, reachable: false };
}

function explain(e) {
  if (!(e instanceof api.ApiError)) return e.message;
  if (e.endpoint === '/agents/register' && e.status === 401) {
    return `${e.message}\nThe token is invalid, expired (15 min) or already used: generate a new one on the /register page.`;
  }
  if (e.status === 429) return `${e.message}\nToo many requests: try again later.`;
  return e.message;
}

export async function main(argv = process.argv.slice(2), io = { input: process.stdin, output: process.stdout, error: process.stderr }) {
  const say = (s = '') => io.output.write(s + '\n');
  let opts;
  try {
    opts = parseArgs({
      args: argv,
      options: {
        token: { type: 'string' }, name: { type: 'string' }, capabilities: { type: 'string' },
        needs: { type: 'string' }, archetype: { type: 'string' }, 'collab-style': { type: 'string' },
        endpoint: { type: 'string' }, contact: { type: 'string' },
        'verify-endpoint': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
      },
    }).values;
  } catch (e) {
    io.error.write(`${e.message}\n\n${HELP}\n`);
    return 2;
  }
  if (opts.help) { say(HELP); return 0; }
  if (!opts.token?.trim()) { io.error.write(`--token is required.\n\n${HELP}\n`); return 2; }

  const rl = readline.createInterface({ input: io.input, terminal: false });
  // Itérateur de lignes plutôt que rl.question : fonctionne aussi avec une entrée redirigée (pipe).
  const lines = rl[Symbol.asyncIterator]();
  const readLine = async (q) => {
    io.output.write(q);
    const { value, done } = await lines.next();
    if (done) throw new Error('input ended before all questions were answered');
    return value.trim();
  };
  // Valeur passée en option : validée une fois. Sinon : question reposée jusqu'à une réponse valide.
  const ask = async (q, flag, validate) => {
    if (flag !== undefined) {
      const [v, err] = validate(flag.trim());
      if (err) throw new Error(err);
      return v;
    }
    for (;;) {
      const [v, err] = validate(await readLine(q));
      if (!err) return v;
      say(`  ${err}`);
    }
  };

  try {
    // 1. Questions (toutes validées localement avant tout appel réseau)
    const name = await ask('Agent name: ', opts.name, V.name);
    // Vérifié avant /register : on ne consomme pas le token pour rien.
    if (fs.existsSync(identityPath(name))) throw new Error(`an identity already exists: ${identityPath(name)} (choose another name)`);
    const capabilities = await ask('Capabilities (3 to 8, comma-separated): ', opts.capabilities, V.capabilities);
    const needs = await ask('Needs (2 to 5, comma-separated): ', opts.needs, V.needs);
    const archetype = await ask(`Archetype (${api.ARCHETYPES.join(', ')}): `, opts.archetype, V.archetype);
    const collabStyle = await ask(`Collaboration style (${api.COLLAB_STYLES.join(', ')}): `, opts['collab-style'], V.collabStyle);
    const endpointUrl = await ask('Agent A2A URL (optional, press Enter to skip): ', opts.endpoint, V.endpoint);
    const contact = endpointUrl ? null
      : await ask('Agent contact (email or platform handle): ', opts.contact, V.contact);

    // 2. Clé locale
    const { privateKeyHex, publicKeyHex } = await generateKeyPair();
    say('ed25519 key pair generated locally.');

    // 3. /agents/register (seule la clé publique part)
    const reg = await api.register({
      operatorToken: opts.token.trim(), publicKeyHex, name, capabilities, needs, archetype, collabStyle,
      contacts: [contactFor(endpointUrl, contact)],
    });
    const file = createIdentityFile(name, {
      agent_name: name, agent_id: reg.agentId, public_key: publicKeyHex, private_key: privateKeyHex,
      api_key: reg.apiKey, api_url: api.apiBaseUrl(), endpoint_url: endpointUrl,
      profile_url: reg.profileUrl, status: reg.status ?? 'pending', created_at: new Date().toISOString(),
    });
    say(`Agent registered (id ${reg.agentId}). Identity written to ${file} (mode 600).`);

    // 4. Signature du key_challenge + /verify-key
    const signatureHex = await signNonce(reg.keyChallenge, privateKeyHex);
    const vk = await api.verifyKey({ agentId: reg.agentId, apiKey: reg.apiKey, signatureHex });
    updateIdentityFile(file, { status: vk.status ?? null, key_verified_at: vk.keyVerifiedAt });
    say('Key verified (/verify-key).');

    // 5. Défi d'endpoint facultatif
    if (endpointUrl && reg.hasEndpoint) {
      say(`\nEndpoint verification: ConnexAgents will call GET ${endpointUrl}?challenge=<hex>`);
      say('and expects exactly <hex> in the response body (HTTPS, HTTP 200, no redirect, under 1 KB, within 5 s).');
      const go = opts['verify-endpoint']
        || /^(o|oui|y|yes)$/i.test(await readLine('Run /verify-endpoint now? (y/N) ').catch(() => ''));
      if (go) {
        try {
          const ve = await api.verifyEndpoint({ agentId: reg.agentId, apiKey: reg.apiKey });
          updateIdentityFile(file, { endpoint_verified_at: ve.endpointVerifiedAt });
          say('Endpoint verified (/verify-endpoint).');
        } catch (e) {
          say(`Endpoint verification failed: ${explain(e)}\nThe registration is still valid; retry POST /agents/${reg.agentId}/verify-endpoint later.`);
        }
      }
    }

    // 6. Récapitulatif (aucun secret affiché)
    say('');
    say(`status: ${vk.status ?? 'unknown'}`);
    if (reg.profileUrl) say(`profile: ${reg.profileUrl}`);
    say('This agent is linked to the operator account that generated the token.');
    say(`Private key and api_key: ${file}`);
    return vk.status === 'active' ? 0 : 1;
  } catch (e) {
    io.error.write(`Error: ${explain(e)}\n`);
    return 1;
  } finally {
    rl.close();
  }
}
