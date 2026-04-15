/**
 * Copyright (c) 2026 NNSEC Sentinel
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from "crypto";

export type VaultRecord = {
  id: string;
  ciphertext: string;
  nonce: string;
  tag: string;
};

export function deriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 32);
}

export function encryptSecret(secret: string, key: Buffer): VaultRecord {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const encrypted = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    id: randomBytes(8).toString("hex"),
    ciphertext: encrypted.toString("base64"),
    nonce: nonce.toString("base64"),
    tag: tag.toString("base64"),
  };
}

export function decryptSecret(record: VaultRecord, key: Buffer): string {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(record.nonce, "base64"));
  decipher.setAuthTag(Buffer.from(record.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
