
import { detectEmails } from "../detectors/email.js";
import { detectPhones } from "../detectors/phone.js";
import { detectCreditCards } from "../detectors/creditCard.js";
import { detectIPs } from "../detectors/ip.js";
import { detectApiKeys } from "../detectors/apiKey.js";
import { assessRisk } from "../utils/risk.js";
import { tokenize, detokenize } from "./tokenizer.js";

const DEFAULT_DETECTORS = {
  email: true,
  phone: true,
  creditCard: true,
  ip: true,
  apiKey: true,
};

/**

 @param {Object} options Engine options
 @returns {Object} Normalized configuration
 */
function normalizeOptions(options = {}) {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options)
  ) {
    throw new TypeError("Options must be an object");
  }

  const {
    country,
    creditCard = {},
    detectors = {},
  } = options;

  if (
    detectors === null ||
    typeof detectors !== "object" ||
    Array.isArray(detectors)
  ) {
    throw new TypeError("Detectors configuration must be an object");
  }

  return {
    country,
    creditCard,
    detectors: {
      ...DEFAULT_DETECTORS,
      ...detectors,
    },
  };
}

/**

 * @param {string} text 
 * @param {Object} options
 * @returns {Object} 
 */
export function scan(text, options = {}) {
  if (typeof text !== "string") {
    throw new TypeError("Input must be a string");
  }

  const config = normalizeOptions(options);
  const findings = [];

  if (config.detectors.email) {
    findings.push(...detectEmails(text));
  }

  if (config.detectors.phone) {
    const phoneOptions = config.country ? { defaultCountry: config.country } : {};
    findings.push(...detectPhones(text, phoneOptions));
  }

  if (config.detectors.creditCard) {
    findings.push(...detectCreditCards(text, config.creditCard));
  }

  if (config.detectors.ip) {
    findings.push(...detectIPs(text));
  }

  if (config.detectors.apiKey) {
    findings.push(...detectApiKeys(text));
  }

  findings.sort((a, b) => a.start - b.start);

  const risk = assessRisk(findings);

  return {
    findings,
    risk,
  };
}

/**
 * Scans text, replaces sensitive spans with reversible tokens, and evaluates risk.
 *
 * @param {string} text Input text
 * @param {Object} options Engine options
 * @returns {Object} { redactedText, tokens, detections, risk }
 */
export function redact(text, options = {}) {
  const { findings, risk } = scan(text, options);
  const { redactedText, tokens, detections } = tokenize(text, findings);

  return {
    redactedText,
    tokens,
    detections,
    risk,
  };
}

/**
 * Restores tokenized text back to its original string using a token map.
 *
 * @param {string} redactedText Text containing INCOGNIX tokens
 * @param {Object} tokens Token-to-value map returned by redact()
 * @returns {string} Restored text
 */
export function restore(redactedText, tokens = {}) {
  return detokenize(redactedText, tokens);
}

/**


 @param {Object} defaultOptions 
 @returns {Object} 
 */
export function createEngine(defaultOptions = {}) {
  const baseConfig = normalizeOptions(defaultOptions);

  const mergeOptions = (callOptions = {}) => {
    const override = normalizeOptions(callOptions);
    return {
      country: override.country ?? baseConfig.country,
      creditCard: { ...baseConfig.creditCard, ...override.creditCard },
      detectors: { ...baseConfig.detectors, ...override.detectors },
    };
  };

  return {
    scan(text, options = {}) {
      return scan(text, mergeOptions(options));
    },
    redact(text, options = {}) {
      return redact(text, mergeOptions(options));
    },
    restore(redactedText, tokens = {}) {
      return restore(redactedText, tokens);
    },
  };
}