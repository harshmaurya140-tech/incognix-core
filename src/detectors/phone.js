
import {
  findPhoneNumbersInText,
  isSupportedCountry
} from "libphonenumber-js/max";

/**
 * INCOGNIX - Phone Number Detector
 *
 * Finds and validates phone numbers in text.
 *
 * @param {string} text - Input text
 * @param {Object} options - Detection configuration
 * @param {string} [options.defaultCountry] - Optional ISO country code
 * @returns {Array<Object>} Detected phone numbers
 */
export function detectPhones(text, options = {}) {
  if (typeof text !== "string") {
    throw new TypeError("Input must be a string");
  }

  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options)
  ) {
    throw new TypeError("Options must be an object");
  }

  const { defaultCountry } = options;

  if (defaultCountry !== undefined) {
    if (
      typeof defaultCountry !== "string" ||
      !isSupportedCountry(defaultCountry)
    ) {
      throw new RangeError("Unsupported default country");
    }
  }

  const searchOptions = defaultCountry
    ? { defaultCountry }
    : {};

  const matches = findPhoneNumbersInText(text, searchOptions);

  return matches
    .filter(({ number }) => number.isValid())
    .map(({ number, startsAt, endsAt }) => ({
      type: "PHONE",
      category: "phone",
      value: text.slice(startsAt, endsAt),
      normalized: number.number,
      country: number.country ?? null,
      extension: number.ext ?? null,
      start: startsAt,
      end: endsAt,
      risk: "high"
    }));
}
