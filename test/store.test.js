import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createIdentityFile, updateIdentityFile, safeName, identityPath } from '../src/store.js';

beforeEach(() => { process.env.CONNEXAGENTS_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'cxr-')); });

test('safeName produit un nom de fichier sûr', () => {
  assert.equal(safeName('Mon Agent Éclair!'), 'mon-agent-eclair');
  assert.equal(safeName('../../etc/passwd'), 'etc-passwd');
  assert.throws(() => safeName('///'));
});

test("createIdentityFile écrit le JSON et refuse d'écraser", () => {
  const file = createIdentityFile('alpha', { private_key: 'aa' });
  assert.equal(file, identityPath('alpha'));
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).private_key, 'aa');
  assert.throws(() => createIdentityFile('alpha', { private_key: 'bb' }), /EEXIST/);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).private_key, 'aa');
});

test('droits 600 sur le fichier et 700 sur le dossier', { skip: process.platform === 'win32' && 'modes POSIX non applicables sous Windows' }, () => {
  const file = createIdentityFile('beta', {});
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  updateIdentityFile(file, { x: 1 });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test('updateIdentityFile fusionne sans perdre la clé', () => {
  const file = createIdentityFile('gamma', { private_key: 'cc', api_key: null });
  updateIdentityFile(file, { api_key: 'k', status: 'active' });
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { private_key: 'cc', api_key: 'k', status: 'active' });
});
