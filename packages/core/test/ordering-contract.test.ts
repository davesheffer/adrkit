/**
 * #115 — `CheckOutcome` promises "identical `(lint, changedFiles, snapshots,
 * markerScans)` produces identical output", and the arrays it carries serialize
 * into `adr check --json`, which `@adrkit/ci` consumes. `localeCompare` orders
 * by the runtime's ICU locale, so two environments could produce different
 * bytes from identical inputs. Every sort on that path must therefore use
 * `compareCodeUnits` (`packages/core/src/ordering/index.ts:12`).
 *
 * The expected orderings below are derived from the comparator's definition —
 * `a < b ? -1 : a > b ? 1 : 0` over UTF-16 code units.
 *
 * ## What this file deliberately does not scan
 *
 * `packages/core/src/affects/**` still contains three `localeCompare` sorts
 * that reach `CheckOutcome` (`compareFiredMatcher`, the match `recordId` sort,
 * and the changed-dependency sort in `matchers/package.ts`). That tree is
 * pinned byte-identical by feature 010's FR-004 guard
 * (`packages/catalog-envelope/test/no-core-schema-change.test.ts`), which names
 * any change there a violation and routes legitimate changes to
 * separately-authorized later work. Those sites stay recorded on #115 until the
 * freeze lifts; scanning them here would only force one guard to break another.
 *
 * `packages/core/src/load/corpus.ts` also still contains three `localeCompare`
 * sorts (`discoverAdrFiles`, `discoverSkippedMarkdownFiles`,
 * `expandRecordInputs`) and also reaches `CheckOutcome`, via `lintCorpus`'s
 * `records`. Not merely display order: `discoverAdrFiles`'s discovery order
 * survives into `lint.records` whenever two records share an id, because the
 * `frontmatter.id` tiebreak `lintCorpus` sorts by is then a no-op and the sort
 * is stable — and `checkChanges` (`toGoverningDecisions`'s `byId` map) picks
 * whichever duplicate landed later as that id's canonical record, changing
 * `governing` / `activeProposals` / `governedBy` by runtime for byte-identical
 * inputs. This file was scoped to #115's `check`/`markers`/`ordering`/`validate`
 * sweep; `load/corpus.ts` is left for a follow-up PR and stays recorded on
 * #115 and unscanned here until that lands.
 */

import { describe, expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { checkChanges, type CheckLintResult } from '../src/check/index.ts';
import { compareCodeUnits } from '../src/ordering/index.ts';
import { sortFindings, type Finding } from '../src/validate/findings.ts';

const emptyLint = (findings: Finding[] = []): CheckLintResult => ({ records: [], findings, checked: 0 });

/** The #115 repro set: names a locale-aware comparison interleaves differently. */
const HOSTILE_FILES = ['src/a_b.ts', 'src/a-b.ts', 'src/a.ts', 'src/A.ts', 'src/ab.ts', 'src/aB.ts'];
const CODE_UNIT_ORDER = ['src/A.ts', 'src/a-b.ts', 'src/a.ts', 'src/aB.ts', 'src/a_b.ts', 'src/ab.ts'];

describe('checkChanges orders changedFiles by code unit, not by locale', () => {
  test('the #115 repro set comes back in code-unit order', () => {
    const outcome = checkChanges({ lint: emptyLint(), changedFiles: HOSTILE_FILES });
    expect(outcome.changedFiles).toEqual(CODE_UNIT_ORDER);
    expect(outcome.changedFiles).toEqual([...HOSTILE_FILES].sort(compareCodeUnits));
  });

  test('the case that separates the two comparators', () => {
    // Every uppercase ASCII letter sorts before every lowercase one by code unit
    // ('Z' is 0x5A, 'a' is 0x61); a locale-aware comparison typically interleaves.
    expect('B'.localeCompare('a')).toBeGreaterThan(0);
    expect(compareCodeUnits('B', 'a')).toBeLessThan(0);

    const outcome = checkChanges({ lint: emptyLint(), changedFiles: ['src/a.ts', 'src/B.ts'] });
    expect(outcome.changedFiles).toEqual(['src/B.ts', 'src/a.ts']);
  });

  test('input order never affects the output', () => {
    const reversed = checkChanges({ lint: emptyLint(), changedFiles: [...HOSTILE_FILES].reverse() });
    expect(reversed.changedFiles).toEqual(CODE_UNIT_ORDER);
  });
});

describe('sortFindings orders every tuple field by code unit', () => {
  const finding = (rule: string, message = 'm'): Finding => ({ rule, severity: 'warn', message });

  test('rules differing only in case sort by code unit', () => {
    const sorted = sortFindings([finding('affects-bad'), finding('Affects-bad')]);
    expect(sorted.map((f) => f.rule)).toEqual(['Affects-bad', 'affects-bad']);
  });

  test('the message tiebreak is code-unit too', () => {
    const sorted = sortFindings([finding('r', 'a_b'), finding('r', 'a-b'), finding('r', 'ab')]);
    expect(sorted.map((f) => f.message)).toEqual(['a-b', 'a_b', 'ab']);
  });

  test('an absent optional field still sorts before any present value', () => {
    const withId: Finding = { ...finding('r'), id: '0001' };
    const sorted = sortFindings([withId, finding('r')]);
    expect(sorted.map((f) => f.id)).toEqual([undefined, '0001']);
  });
});

describe('the check --json path never reaches for localeCompare', () => {
  // The same source-scan shape as the adapter's
  // `test/glob-order.test.ts` guard, widened to every core module that feeds
  // `CheckOutcome`: `check/`, `markers/`, `ordering/`, and the shared finding
  // sort. See the header for why `affects/` and `load/corpus.ts` are excluded
  // for now.
  const SCANNED_DIRS = ['src/check', 'src/markers', 'src/ordering'];
  const SCANNED_FILES = ['src/validate/findings.ts'];

  function tsFilesUnder(relativeDir: string): string[] {
    const root = join(import.meta.dir, '..', relativeDir);
    const found: string[] = [];
    const walk = (dir: string, prefix: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
        const next = `${prefix}${entry.name}`;
        if (entry.isDirectory()) walk(join(dir, entry.name), `${next}/`);
        else if (entry.name.endsWith('.ts')) found.push(`${relativeDir}/${next}`);
      }
    };
    walk(root, '');
    return found;
  }

  const scanned = [...SCANNED_DIRS.flatMap(tsFilesUnder), ...SCANNED_FILES];

  test('the scan examined a non-trivial module list', () => {
    // Report what was examined, not only what was concluded (ADR-0016 clause 3):
    // an empty walk would make the per-file assertions below vacuous.
    expect(scanned.length).toBeGreaterThanOrEqual(8);
    expect(scanned).toContain('src/check/index.ts');
    expect(scanned).toContain('src/markers/resolve.ts');
    expect(scanned).toContain('src/validate/findings.ts');
  });

  for (const file of scanned) {
    test(`${file} sorts with compareCodeUnits only`, () => {
      const source = readFileSync(join(import.meta.dir, '..', file), 'utf8');
      const code = source.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/\/\/[^\n]*/gu, '');
      expect(code).not.toContain('localeCompare');
    });
  }
});
