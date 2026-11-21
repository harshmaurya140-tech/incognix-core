/**
 * INCOGNIX - API Key & Secret Detector
 * Detects common API keys, access tokens, and high-sensitivity credentials in text.
 */

const API_KEY_PATTERNS = [
  {
    provider: "anthropic",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    risk: "critical",
  },
  {
    provider: "openai",
    pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
    risk: "critical",
  },
  {
    provider: "github",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
    risk: "critical",
  },
  {
    provider: "aws",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    risk: "critical",
  },
  {
    provider: "stripe",
    pattern: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,
    risk: "critical",
  },
  {
    provider: "google",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    risk: "high",
  },
];
/**
 * Detects API keys and secrets in text.
 *
 * @param {string} text Input text
 * @returns {Array<Object>} Detected API key results
 */
export function detectApiKeys(text) {
  if (typeof text !== "string") {
    throw new TypeError("Input must be a string");
  }

  const results = [];
  const seenRanges = new Set();

  for (const { provider, pattern, risk } of API_KEY_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);

    for (const match of text.matchAll(regex)) {
      const value = match[0];
      const start = match.index;
      const end = start + value.length;
      const rangeKey = `${start}:${end}`;

      if (seenRanges.has(rangeKey)) {
        continue;
      }

      seenRanges.add(rangeKey);

      results.push({
        type: "API_KEY",
        category: "secret",
        provider,
        value,
        start,
        end,
        risk,
      });
    }
  }

  return results.sort((a, b) => a.start - b.start);
}