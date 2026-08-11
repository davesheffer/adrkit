// Runtime-acyclic: `../ordering/index.ts` imports `Finding` from here type-only.
import { compareCodeUnits } from '../ordering/index.ts';

export const IMPORT_FINDING_RULES = [
  'import-incomplete',
  'import-status-unrecognized',
  'import-date-missing',
  'import-deciders-unmapped',
  'import-undiscoverable',
  'import-not-madr',
] as const;

export type ImportFindingRule = (typeof IMPORT_FINDING_RULES)[number];

export type FindingSeverity = 'error' | 'warn' | 'info';

export interface Finding {
  rule: string;
  severity: FindingSeverity;
  message: string;
  path?: string;
  id?: string;
  field?: string;
  pattern?: string;
}

function compareOptional(a: string | undefined, b: string | undefined): number {
  return compareCodeUnits(a ?? '', b ?? '');
}

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      compareCodeUnits(a.rule, b.rule) ||
      compareOptional(a.id, b.id) ||
      compareOptional(a.pattern, b.pattern) ||
      compareOptional(a.path, b.path) ||
      compareOptional(a.field, b.field) ||
      compareCodeUnits(a.message, b.message),
  );
}

export function countFindings(findings: readonly Finding[]): { errors: number; warnings: number; infos: number } {
  let errors = 0;
  let warnings = 0;
  let infos = 0;
  for (const finding of findings) {
    if (finding.severity === 'error') errors += 1;
    if (finding.severity === 'warn') warnings += 1;
    if (finding.severity === 'info') infos += 1;
  }
  return { errors, warnings, infos };
}

export function exitCodeForFindings(findings: readonly Finding[]): 0 | 1 {
  return findings.some((finding) => finding.severity === 'error') ? 1 : 0;
}
