/**
 * Heuristic risk calculation and verdict classification engine.
 * Transparent, configurable weights and thresholds.
 */

export const RISK_CONFIG = {
  maxScore: 100,
  thresholds: {
    noWarningMax: 24,
    someWarningMax: 54,
    highConcernMin: 55
  },
  verdicts: {
    NONE_DETECTED: {
      code: 'NONE_DETECTED',
      label: 'No Obvious Warning Signs Detected',
      plainVerdict: 'No obvious warning signs detected — this does not guarantee safety.',
      severity: 'Neutral',
      themeKey: 'neutral',
      summary: 'Our structural heuristic checks did not uncover common deceptive patterns or obfuscation techniques.',
      disclaimer: 'This is not proof of safety. Local analysis cannot detect zero-day exploits, compromised legitimate sites, domain reputation history, or live server payloads.'
    },
    SOME_WARNINGS: {
      code: 'SOME_WARNINGS',
      label: 'Some Warning Signs',
      plainVerdict: 'Some warning signs — review this link carefully.',
      severity: 'Moderate',
      themeKey: 'warning',
      summary: 'Several non-standard or obfuscated patterns were detected in the URL structure.',
      disclaimer: 'These patterns occur in both legitimate utility links (such as shorteners and tracking redirects) and deceptive links. Exercise caution and verify the source.'
    },
    HIGH_CONCERN: {
      code: 'HIGH_CONCERN',
      label: 'High Concern',
      plainVerdict: 'High concern — several suspicious signs detected.',
      severity: 'High',
      themeKey: 'danger',
      summary: 'Multiple significant deception signals or high-risk structural anomalies were identified.',
      disclaimer: 'Heuristic analysis indicates strong structural indicators commonly used in credential harvesting or redirection scams. Do not click or submit sensitive information.'
    }
  }
};

/**
 * Calculates a composite heuristic risk score and returns verdict metadata.
 * @param {Array<object>} findings 
 * @returns {{
 *   score: number,
 *   verdict: object,
 *   breakdown: Array<{ id: string, title: string, weight: number, severity: string }>
 * }}
 */
export function calculateRiskScore(findings = []) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return {
      score: 0,
      verdict: RISK_CONFIG.verdicts.NONE_DETECTED,
      breakdown: []
    };
  }

  // Sum unique weights, capping individual severities if necessary
  let rawScore = 0;
  const breakdown = [];

  for (const finding of findings) {
    const weight = typeof finding.weight === 'number' ? finding.weight : 0;
    rawScore += weight;
    breakdown.push({
      id: finding.id,
      title: finding.title,
      weight,
      severity: finding.severity
    });
  }

  // Cap score strictly at 100
  const finalScore = Math.min(RISK_CONFIG.maxScore, Math.max(0, Math.round(rawScore)));

  // Determine verdict
  let verdict;
  if (finalScore >= RISK_CONFIG.thresholds.highConcernMin) {
    verdict = RISK_CONFIG.verdicts.HIGH_CONCERN;
  } else if (finalScore >= RISK_CONFIG.thresholds.noWarningMax + 1) {
    verdict = RISK_CONFIG.verdicts.SOME_WARNINGS;
  } else {
    verdict = RISK_CONFIG.verdicts.NONE_DETECTED;
  }

  return {
    score: finalScore,
    verdict,
    breakdown
  };
}
