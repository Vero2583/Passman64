import crypto from "crypto";

const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

const keyStore = new Map();

const KEY_TTL_MS = 60 * 60 * 1000;

export function storeUserKey(userId, masterPassword) {
  const key = crypto.createHash("sha256").update(masterPassword).digest();

  keyStore.set(userId, {
    key,
    expiresAt: Date.now() + KEY_TTL_MS,
  });
}

export function getUserKey(userId) {
  const stored = keyStore.get(userId);

  if (!stored) return null;

  if (Date.now() > stored.expiresAt) {
    keyStore.delete(userId);
    return null;
  }

  return stored.key;
}

export function removeUserKey(userId) {
  keyStore.delete(userId);
}

export function encryptPassword(plaintext, masterKey) {
  const initialisation_vector = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    masterKey,
    initialisation_vector,
    { authTagLength: AUTH_TAG_LENGTH }
  );

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();
  const encryptedWithTag = Buffer.concat([encrypted, authTag]);

  return {
    encrypted: encryptedWithTag.toString("hex"),
    initialisation_vector: initialisation_vector.toString("hex"),
  };
}

export function decryptPassword(
  encryptedHex,
  initialisationVectorHex,
  masterKey
) {
  const encryptedWithTag = Buffer.from(encryptedHex, "hex");
  const initialisation_vector = Buffer.from(initialisationVectorHex, "hex");

  const authTag = encryptedWithTag.subarray(
    encryptedWithTag.length - AUTH_TAG_LENGTH
  );

  const encrypted = encryptedWithTag.subarray(
    0,
    encryptedWithTag.length - AUTH_TAG_LENGTH
  );

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    masterKey,
    initialisation_vector,
    { authTagLength: AUTH_TAG_LENGTH }
  );

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}
