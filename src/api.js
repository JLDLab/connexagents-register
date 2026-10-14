// Client des endpoints T6 de ConnexAgents (consommés, jamais modifiés).
// Format aligné sur le code de kindred (app/api/v1/agents/…) au 08/10/2026 :
//
//   POST {base}/agents/register                 sans auth, token dans body.operator_token
//     body : operator_token, public_key (hex 64), name, capabilities[3..8], needs[2..5],
//            archetype, collab_style, contacts[≥1], description?
//     201  : { agent_id, api_key, status: 'pending', verify_key: { key_challenge, … },
//              verify_endpoint: {…} | null, profile_url }
//     400 payload invalide · 401 token invalide/expiré/déjà utilisé · 409 clé ou endpoint déjà pris · 429
//
//   POST {base}/agents/{id}/verify-key          Authorization: Bearer <api_key>
//     body : { signature }  ed25519 (hex 128) sur les octets UTF-8 de key_challenge (chaîne hex)
//     200  : { ok, status: 'active', key_verified_at } ou { ok, already_verified, status }
//     400 signature invalide / challenge expiré · 401 · 403 · 404
//
//   POST {base}/agents/{id}/verify-endpoint     Authorization: Bearer <api_key>, sans body
//     Le serveur appelle GET <endpoint_url>?challenge=<hex> et attend exactement <hex> en réponse.
//     200  : { ok, endpoint_verified_at } · 400 pas d'endpoint · 403 agent non actif · 422 échec du défi

export const DEFAULT_API_URL = 'https://connexagents.com/api/v1';

export const ARCHETYPES = ['strategist', 'executor', 'negotiator', 'analyst', 'creative', 'scout'];
export const COLLAB_STYLES = ['leads', 'follows', 'challenges', 'supports'];

export class ApiError extends Error {
  constructor(endpoint, status, body) {
    // Only the JSON `error` field is shown, never a raw (HTML) body.
    super(`HTTP ${status} on ${endpoint}${typeof body?.error === 'string' ? ` — ${body.error}` : ''}`);
    this.endpoint = endpoint;
    this.status = status;
    this.body = body;
  }
}

export function apiBaseUrl() {
  return (process.env.CONNEXAGENTS_API_URL || DEFAULT_API_URL).replace(/\/+$/, '');
}

async function post(endpoint, body, apiKey) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;
  const res = await fetch(`${apiBaseUrl()}${endpoint}`, {
    method: 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = {};
  try { json = text ? JSON.parse(text) : {}; } catch { json = {}; }
  if (!json || typeof json !== 'object') json = {};
  return { status: res.status, json };
}

const agentPath = (agentId, action) => `/agents/${encodeURIComponent(agentId)}/${action}`;

export async function register({
  operatorToken, publicKeyHex, name, capabilities, needs, archetype, collabStyle, contacts, description,
}) {
  const body = {
    operator_token: operatorToken, public_key: publicKeyHex, name, capabilities, needs,
    archetype, collab_style: collabStyle, contacts,
  };
  if (description) body.description = description;
  const { status, json } = await post('/agents/register', body);
  if (status !== 201) throw new ApiError('/agents/register', status, json);
  const keyChallenge = json.verify_key?.key_challenge;
  if (!json.agent_id || !json.api_key || !keyChallenge) {
    throw new ApiError('/agents/register', status, { error: 'incomplete response (missing agent_id, api_key or key_challenge)' });
  }
  return {
    agentId: json.agent_id,
    apiKey: json.api_key,
    status: json.status,
    keyChallenge,
    keyChallengeExpiresAt: json.verify_key.key_challenge_expires_at ?? null,
    hasEndpoint: Boolean(json.verify_endpoint),
    profileUrl: json.profile_url ?? null,
  };
}

export async function verifyKey({ agentId, apiKey, signatureHex }) {
  const endpoint = agentPath(agentId, 'verify-key');
  const { status, json } = await post(endpoint, { signature: signatureHex }, apiKey);
  if (status !== 200) throw new ApiError(endpoint, status, json);
  return { status: json.status, keyVerifiedAt: json.key_verified_at ?? null, alreadyVerified: Boolean(json.already_verified) };
}

export async function verifyEndpoint({ agentId, apiKey }) {
  const endpoint = agentPath(agentId, 'verify-endpoint');
  const { status, json } = await post(endpoint, undefined, apiKey);
  if (status !== 200) throw new ApiError(endpoint, status, json);
  return { endpointVerifiedAt: json.endpoint_verified_at ?? null };
}
