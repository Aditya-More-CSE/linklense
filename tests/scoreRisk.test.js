import { describe, it, expect } from 'vitest';
import { calculateRiskScore, RISK_CONFIG } from '../src/analyzer/scoreRisk.js';

describe('scoreRisk', () => {
  it('returns 0 and NONE_DETECTED when no findings exist', () => {
    const result = calculateRiskScore([]);
    expect(result.score).toBe(0);
    expect(result.verdict.code).toBe('NONE_DETECTED');
    expect(result.verdict.label).toBe('No Obvious Warning Signs Detected');
  });

  it('keeps informational HTTP usage within No Obvious Warning Signs threshold', () => {
    const httpFinding = [{
      id: 'insecure-http',
      title: 'Unencrypted HTTP Transport',
      severity: 'Informational',
      weight: 5
    }];
    const result = calculateRiskScore(httpFinding);
    expect(result.score).toBe(5);
    expect(result.verdict.code).toBe('NONE_DETECTED');
  });

  it('classifies moderate findings into Some Warning Signs (25–54)', () => {
    const findings = [
      { id: 'url-shortener', severity: 'Moderate', weight: 20 },
      { id: 'redirect-parameter', severity: 'Low', weight: 10 }
    ];
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(30);
    expect(result.verdict.code).toBe('SOME_WARNINGS');
  });

  it('classifies serious combined findings into High Concern (55–100)', () => {
    const findings = [
      { id: 'user-info-deception', severity: 'High', weight: 35 },
      { id: 'ip-host', severity: 'Moderate', weight: 20 },
      { id: 'hostname-complexity', severity: 'Moderate', weight: 15 }
    ];
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(70);
    expect(result.verdict.code).toBe('HIGH_CONCERN');
  });

  it('caps scores strictly at 100', () => {
    const findings = [
      { id: '1', weight: 40 },
      { id: '2', weight: 40 },
      { id: '3', weight: 40 }
    ];
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(100);
  });
});
