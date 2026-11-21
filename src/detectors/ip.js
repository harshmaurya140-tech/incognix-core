
import { isIP } from "node:net";

/**
 * INCOGNIX - IP Address Detector
 *
 * Detects valid IPv4 and IPv6 addresses in text.
 */

const IPV4_PATTERN =
  /(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9.])/g;

const IPV6_PATTERN =
  /(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:.])/g;

/**
 * Detects IP addresses in text.
 *
 * @param {string} text - Input text
 * @returns {Array<Object>} Detected IP addresses
 */
export function detectIPs(text) {
  if (typeof text !== "string") {
    throw new TypeError("Input must be a string");
  }

  const results = [];
  const patterns = [IPV4_PATTERN, IPV6_PATTERN];

  for (const pattern of patterns) {
    // Create a fresh regex so repeated calls don't share lastIndex.
    const regex = new RegExp(pattern.source, pattern.flags);

    for (const match of text.matchAll(regex)) {
      const address = match[0];
      const version = isIP(address);

      if (version === 0) {
        continue;
      }

      const start = match.index;
      const end = start + address.length;

      results.push({
        type: "IP_ADDRESS",
        category: "ip",
        value: address,
        version,
        start,
        end,
        risk: "medium"
      });
    }
  }

  // Keep results in their original text order.
  return results.sort((a, b) => a.start - b.start);
}
