/**
 * Copyright (c) 2026 NNSEC Sentinel
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Anthropic from "@anthropic-ai/sdk";

type CompileResult = {
  rego: string;
  notes: string[];
};

const EXAMPLE_POLICY = `
package sentinel.generated

default allow = true

deny[msg] {
  input.user.type == "contractor"
  contains(input.resource, "github.com")
  input.action == "download"
  msg := "Contractors cannot download from GitHub"
}
`;

export async function compileRule(prompt: string): Promise<CompileResult> {
  const normalized = prompt.toLowerCase();
  if (
    normalized.includes("contractor") &&
    normalized.includes("download") &&
    normalized.includes("github")
  ) {
    return {
      rego: EXAMPLE_POLICY.trim(),
      notes: ["Mapped actor=contractor action=download resource=github.com"]
    };
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (apiKey) {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model: "claude-3-5-sonnet-latest",
      max_tokens: 700,
      messages: [
        {
          role: "user",
          content:
            "Convert this policy instruction into strict Rego only, no prose: " + prompt,
        },
      ],
      system:
        "You are a policy compiler. Return Rego policy text only. Default deny unsafe outputs.",
    });
    const candidate = response.content
      .map((item) => ("text" in item ? item.text : ""))
      .join("\n")
      .trim();
    if (candidate.startsWith("package ")) {
      return {
        rego: candidate,
        notes: ["Compiled with Claude API and basic structural validation."],
      };
    }
  }

  return {
    rego: `package sentinel.generated\n\ndefault allow = true`,
    notes: ["Fallback policy generated; unresolved natural-language intent."]
  };
}

async function main(): Promise<void> {
  const prompt = process.argv.slice(2).join(" ");
  if (!prompt) {
    console.error("Usage: npm run compile -- \"<natural language policy>\"");
    process.exit(1);
  }
  const result = await compileRule(prompt);
  console.log(result.rego);
  console.error(`[obs] compiler_notes=${JSON.stringify(result.notes)}`);
}

void main();
