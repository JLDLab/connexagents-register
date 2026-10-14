// Génération de clé et signature ed25519, entièrement locale.
import * as ed from '@noble/ed25519';

const { bytesToHex, hexToBytes } = ed.etc;

// Retourne { privateKeyHex, publicKeyHex }. La clé privée ne doit jamais
// quitter ce processus autrement que vers le fichier local (store.js).
export async function generateKeyPair() {
  const secretKey = ed.utils.randomSecretKey();
  const publicKey = await ed.getPublicKeyAsync(secretKey);
  return { privateKeyHex: bytesToHex(secretKey), publicKeyHex: bytesToHex(publicKey) };
}

// Signe le nonce (chaîne UTF-8) renvoyé par /register. Retourne la signature en hex.
export async function signNonce(nonce, privateKeyHex) {
  if (typeof nonce !== 'string' || nonce.length === 0) throw new Error('missing nonce');
  const sig = await ed.signAsync(new TextEncoder().encode(nonce), hexToBytes(privateKeyHex));
  return bytesToHex(sig);
}

export async function verifySignature(signatureHex, nonce, publicKeyHex) {
  return ed.verifyAsync(hexToBytes(signatureHex), new TextEncoder().encode(nonce), hexToBytes(publicKeyHex));
}
