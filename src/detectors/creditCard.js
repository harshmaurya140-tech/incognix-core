
/**
 * INCOGNIX - Credit Card Detector
 *
 * Detects card-number candidates and validates them
 * using the Luhn checksum algorithm.
 */

const DEFAULT_MIN_LENGTH = 13;
const DEFAULT_MAX_LENGTH = 19;

function validateOptions(options) {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options)
  ) {
    throw new TypeError("Options must be an object");
  }

  const {
    minLength = DEFAULT_MIN_LENGTH,
    maxLength = DEFAULT_MAX_LENGTH
  } = options;

  if (
    !Number.isInteger(minLength) ||
    !Number.isInteger(maxLength) ||
    minLength < 1 ||
    maxLength > 19 ||
    minLength > maxLength
  ) {
    throw new RangeError("Invalid card-number length configuration");
  }

  return { minLength, maxLength };
}

/**
 * Validates a numeric candidate using the Luhn algorithm.
 */
export function passesLuhn(number) {
  if (typeof number !== "string" || !/^\d+$/.test(number)) {
    return false;
  }

  let sum = 0;
  let doubleDigit = false;

  for (let i = number.length - 1; i >= 0; i--) {
    let digit = Number(number[i]);

    if (doubleDigit) {
      digit *= 2;

      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    doubleDigit = !doubleDigit;
  }

  return sum % 10 === 0;
}

/**
 * Detects potential credit card numbers in text.
 *
 * @param {string} text - Input text
 * @param {Object} options - Detection configuration
 * @returns {Array<Object>} Detection results
 */
export function detectCreditCards(text, options = {}) {
  if (typeof text !== "string") {
    throw new TypeError("Input must be a string");
  }

  const { minLength, maxLength } = validateOptions(options);

  const pattern = /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g;

  const results = [];

  for (const match of text.matchAll(pattern)) {
    const candidate = match[0];
    const digits = candidate.replace(/[ -]/g, "");

    if (
      digits.length < minLength ||
      digits.length > maxLength
    ) {
      continue;
    }

    // Reject candidates containing only repeated digits.
    if (/^(\d)\1+$/.test(digits)) {
      continue;
    }

    if (!passesLuhn(digits)) {
      continue;
    }

    results.push({
      type: "CREDIT_CARD",
      category: "payment_card",
      value: candidate,
      start: match.index,
      end: match.index + candidate.length,
      risk: "high"
    });
  }

  return results;
}
