/**
 * INCOGNIX - Risk Scoring Engine
 * Evaluates aggregate privacy exposure from detector findings.
 */

const RISK_WEIGHTS = {
  low: 10,
  medium: 25,
  high: 50,
  critical: 85,
};

const RISK_RANK = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const ADDITIONAL_FINDING_PENALTY = 10;
const MAX_RISK_SCORE = 100;

/**
 * Calculates an aggregate risk assessment from detector findings.
 *
 * @param {Array<Object>} findings Detection objects from INCOGNIX detectors
 * @returns {Object} Risk summary containing score, level, totalFindings, and breakdown
 */
export function assessRisk(findings = []) {
  if (!Array.isArray(findings)) {
    throw new TypeError("Findings must be an array");
  }

  if (findings.length === 0) {
    return {
      score: 0,
      level: "none",
      totalFindings: 0,
      breakdown: {},
    };
  }

  let highestLevel = "low";
  let highestWeight = 0;
  const breakdown = {};

  for (const item of findings) {
    if (!item || typeof item !== "object") {
      throw new TypeError("Each finding must be an object");
    }

    const level = item.risk && item.risk in RISK_WEIGHTS ? item.risk : "low";
    const weight = RISK_WEIGHTS[level];

    if (RISK_RANK[level] > RISK_RANK[highestLevel]) {
      highestLevel = level;
    }

    if (weight > highestWeight) {
      highestWeight = weight;
    }

    const category = item.type || "UNKNOWN";
    breakdown[category] = (breakdown[category] || 0) + 1;
  }

  const rawScore =
    highestWeight + (findings.length - 1) * ADDITIONAL_FINDING_PENALTY;
  const score = Math.min(rawScore, MAX_RISK_SCORE);

  return {
    score,
    level: highestLevel,
    totalFindings: findings.length,
    breakdown,
  };
}