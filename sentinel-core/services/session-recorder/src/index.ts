/**
 * Copyright (c) NNSEC Sentinel.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { record } from "rrweb";
import { createCipheriv, randomBytes, scryptSync } from "crypto";

type Uploader = (payload: Buffer) => Promise<void>;

export interface RecorderConfig {
  tenantId: string;
  sessionId: string;
  passphrase: string;
  uploader: Uploader;
}

export function startRecorder(config: RecorderConfig): () => void {
  const events: unknown[] = [];
  const stop = record({
    emit(event) {
      events.push(event);
    },
  });

  const flush = async (): Promise<void> => {
    const iv = randomBytes(12);
    const salt = randomBytes(16);
    const key = scryptSync(config.passphrase, salt, 32);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const clear = Buffer.from(JSON.stringify(events), "utf8");
    const encrypted = Buffer.concat([cipher.update(clear), cipher.final()]);
    const tag = cipher.getAuthTag();

    const envelope = Buffer.concat([salt, iv, tag, encrypted]);
    await config.uploader(envelope);
  };

  window.addEventListener("beforeunload", () => {
    void flush();
  });

  return () => {
    stop();
    void flush();
  };
}
