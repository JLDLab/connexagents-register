// Écriture du fichier d'identité ~/.connexagents/<agent>.json (droits 600).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function configDir() {
  return process.env.CONNEXAGENTS_HOME || path.join(os.homedir(), '.connexagents');
}

// Nom de fichier sûr dérivé du nom de l'agent.
export function safeName(agentName) {
  const s = String(agentName).toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 64);
  if (!s) throw new Error('agent name cannot be turned into a valid file name');
  return s;
}

export function identityPath(agentName) {
  return path.join(configDir(), `${safeName(agentName)}.json`);
}

// Création exclusive : refuse d'écraser une identité existante (on ne détruit jamais une clé).
export function createIdentityFile(agentName, data) {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = identityPath(agentName);
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  fs.chmodSync(file, 0o600); // au cas où l'umask aurait restreint autrement
  return file;
}

export function updateIdentityFile(file, patch) {
  const data = { ...JSON.parse(fs.readFileSync(file, 'utf8')), ...patch };
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
  return data;
}
