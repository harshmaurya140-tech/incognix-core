
/**
 * INCOGNIX - Email Detector
 *
 * Detects email addresses in a given text.
 * This is pattern-based detection, not full RFC email validation.
 */

const EMAIL_REGEX =
  /(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+(?![A-Z0-9.!#$%&'*+/=?^_`{|}~-])/gi;

/**
 * Detect email addresses from text.
 *
 * @param {string} text - Input text
 * @returns {Array<Object>} Detected email information
 */

export function detectEmails(text) {
  if (typeof text !== "string") {
    throw new TypeError("Input must be a string");
  }

  const results = [];

  const matches = text.matchAll(EMAIL_REGEX);

  for (const match of matches) {
    const email = match[0];
    const [localPart] = email.split("@");

    // Reject malformed local parts.
    if (
      localPart.startsWith(".") ||
      localPart.endsWith(".") ||
      localPart.includes("..")
    ) {
      continue;
    }

    results.push({
      type: "EMAIL",
      category: "email",
      value: email,
      start: match.index,
      end: match.index + email.length,
      risk: "medium"
    });
  }

  return results;
}
