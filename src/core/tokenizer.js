const RISK_PRIORITY = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 Resolves overlapping detector matches by keeping higher-risk or longer spans first,
 then sorting cleanly in text order.

 @param {Array<Object>} findings
 @returns {Array<Object>}
 */


function resolveOverlaps(findings) {
  const ranked = [...findings].sort((a, b) => {
    if (a.start !== b.start) {
      return a.start - b.start;
    }

    const riskDiff =
      (RISK_PRIORITY[b.risk] || 0) - (RISK_PRIORITY[a.risk] || 0);
    if (riskDiff !== 0) {
      return riskDiff;
    }

    return b.end - b.start - (a.end - a.start);
  });

  const resolved = [];
  let lastEnd = -1;

  for (const item of ranked) {
    if (
      typeof item.start !== "number" ||
      typeof item.end !== "number" ||
      item.start < 0 ||
      item.end <= item.start
    ) {
      throw new TypeError("Each finding must have valid start and end offsets");
    }

    if (item.start < lastEnd) {
      continue;
    }

    resolved.push(item);
    lastEnd = item.end;
  }

  return resolved;
}

/**

 * @param {string} text 
 * @param {Array<Object>} findings 
 * @returns {Object} 
 */
export function tokenize(text, findings = []) {
  if (typeof text !== "string") {
    throw new TypeError("Input text must be a string");
  }

  if (!Array.isArray(findings)) {
    throw new TypeError("Findings must be an array");
  }

  if (findings.length === 0) {
    return {
      redactedText: text,
      tokens: {},
      detections: [],
    };
  }

  const cleanFindings = resolveOverlaps(findings);
  const typeCounters = {};
  const valueToToken = new Map();
  const tokens = {};
  const detections = [];

  let cursor = 0;
  let redactedText = "";

  for (const item of cleanFindings) {
    const originalValue = text.slice(item.start, item.end);
    const type = item.type || "REDACTED";
    const lookupKey = `${type}:${originalValue}`;

    let token = valueToToken.get(lookupKey);

    if (!token) {
      typeCounters[type] = (typeCounters[type] || 0) + 1;
      token = `[${type}_${typeCounters[type]}]`;
      valueToToken.set(lookupKey, token);
      tokens[token] = originalValue;
    }

    redactedText += text.slice(cursor, item.start) + token;
    cursor = item.end;

    detections.push({
      ...item,
      token,
    });
  }

  redactedText += text.slice(cursor);

  return {
    redactedText,
    tokens,
    detections,
  };
}

/**

 * @param {string} redactedText
 * @param {Object} tokens 
 * @returns {string} 
 */
export function detokenize(redactedText, tokens = {}) {
  if (typeof redactedText !== "string") {
    throw new TypeError("Redacted text must be a string");
  }

  if (tokens === null || typeof tokens !== "object" || Array.isArray(tokens)) {
    throw new TypeError("Tokens must be a plain object");
  }

  let restored = redactedText;

  for (const [token, originalValue] of Object.entries(tokens)) {
    restored = restored.split(token).join(originalValue);
  }

  return restored;
}