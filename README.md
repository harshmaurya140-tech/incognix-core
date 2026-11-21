# incognix-core

A zero-cloud, local-first JavaScript privacy protection and reversible PII redaction engine for AI prompts, logs, and backend pipelines.

## Installation

```bash
npm install incognix-core
import { redact, restore, scan, createEngine } from "incognix-core";

const prompt =
  "Email harsh@example.com or call +91 9876543210 with key sk-proj-1234567890abcdefghijklmnop";

// 1. Redact sensitive data into reversible tokens
const { redactedText, tokens, risk } = redact(prompt);
console.log(redactedText);
// -> "Email [EMAIL_1] or call [PHONE_1] with key [API_KEY_1]"
console.log(risk);
// -> { score: 100, level: "critical", totalFindings: 3, breakdown: { EMAIL: 1, PHONE: 1, API_KEY: 1 } }

// 2. Restore original values locally after LLM processing
const restored = restore(redactedText, tokens);
console.log(restored === prompt); // true


const engine = createEngine({
  country: "IN",
  detectors: { ip: false },
});

const result = engine.scan("Call 9876543210");