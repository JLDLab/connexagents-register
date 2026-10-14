import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as ed from '@noble/ed25519';
import { generateKeyPair, signNonce, verifySignature } from '../src/keys.js';

test('generateKeyPair produit des clés hex de 32 octets', async () => {
  const { privateKeyHex, publicKeyHex } = await generateKeyPair();
  assert.match(privateKeyHex, /^[0-9a-f]{64}$/);
  assert.match(publicKeyHex, /^[0-9a-f]{64}$/);
  assert.notEqual(privateKeyHex, publicKeyHex);
});

test('deux générations donnent des clés différentes', async () => {
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  assert.notEqual(a.privateKeyHex, b.privateKeyHex);
  assert.notEqual(a.publicKeyHex, b.publicKeyHex);
});

test('la clé publique dérive bien de la clé privée', async () => {
  const { privateKeyHex, publicKeyHex } = await generateKeyPair();
  assert.equal(ed.etc.bytesToHex(await ed.getPublicKeyAsync(ed.etc.hexToBytes(privateKeyHex))), publicKeyHex);
});

test('la signature du nonce est vérifiable avec la clé publique', async () => {
  const { privateKeyHex, publicKeyHex } = await generateKeyPair();
  const sig = await signNonce('nonce-123', privateKeyHex);
  assert.match(sig, /^[0-9a-f]{128}$/);
  assert.equal(await verifySignature(sig, 'nonce-123', publicKeyHex), true);
});

test('la signature échoue sur un autre nonce ou une autre clé', async () => {
  const k1 = await generateKeyPair();
  const k2 = await generateKeyPair();
  const sig = await signNonce('nonce-123', k1.privateKeyHex);
  assert.equal(await verifySignature(sig, 'nonce-124', k1.publicKeyHex), false);
  assert.equal(await verifySignature(sig, 'nonce-123', k2.publicKeyHex), false);
});

test('signature déterministe (RFC 8032)', async () => {
  const { privateKeyHex } = await generateKeyPair();
  assert.equal(await signNonce('n', privateKeyHex), await signNonce('n', privateKeyHex));
});

test('vecteur RFC 8032 section 7.1, TEST 2 (message 0x72 = "r")', async () => {
  const sk = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
  const pk = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
  const expected = '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
    + '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00';
  assert.equal(ed.etc.bytesToHex(await ed.getPublicKeyAsync(ed.etc.hexToBytes(sk))), pk);
  assert.equal(await signNonce('r', sk), expected);
  assert.equal(await verifySignature(expected, 'r', pk), true);
});

test('signNonce refuse un nonce vide ou absent', async () => {
  const { privateKeyHex } = await generateKeyPair();
  await assert.rejects(signNonce('', privateKeyHex));
  await assert.rejects(signNonce(undefined, privateKeyHex));
});
