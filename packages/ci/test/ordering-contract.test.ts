/**
 * #115 — the Action feeds `changedFiles` / `markerFiles` / `changedDependencies`
 * into `checkChanges`, whose output is a determinism contract: identical inputs
 * must produce identical bytes. `localeCompare` orders by the runtime's ICU
 * locale, so these lists must be sorted with `compareCodeUnits` instead —
 * otherwise the same PR renders a different comment on a differently-configured
 * runner.
 */

import { describe, expect, test } from 'bun:test';
import { compareCodeUnits } from '@adrkit/core';
import { extractChanges } from '../src/changed-files.ts';
import type { PrFile } from '../src/github.ts';
import { makeFakeClient } from './fake-github.ts';

function clientWithFiles(files: PrFile[]) {
  return makeFakeClient({ files });
}

describe('extractChanges orders by code unit, not by locale', () => {
  test('the #115 repro set comes back in code-unit order', async () => {
    const client = clientWithFiles([
      { filename: 'src/a_b.ts' },
      { filename: 'src/a-b.ts' },
      { filename: 'src/a.ts' },
      { filename: 'src/A.ts' },
      { filename: 'src/ab.ts' },
      { filename: 'src/aB.ts' },
    ]);

    const changes = await extractChanges(client);

    const expected = ['src/A.ts', 'src/a-b.ts', 'src/a.ts', 'src/aB.ts', 'src/a_b.ts', 'src/ab.ts'];
    expect(changes.changedFiles).toEqual(expected);
    expect(changes.markerFiles).toEqual(expected);
  });

  test('a rename’s previous path obeys the same order', async () => {
    // 'Z' (0x5A) sorts before 'a' (0x61) by code unit; localeCompare typically
    // puts it after — this is the case that separates the two comparators.
    const client = clientWithFiles([
      { filename: 'src/a.ts', previousFilename: 'src/Z.ts', status: 'renamed' },
    ]);

    const changes = await extractChanges(client);

    expect(changes.changedFiles).toEqual(['src/Z.ts', 'src/a.ts']);
    expect([...changes.changedFiles].sort(compareCodeUnits)).toEqual(changes.changedFiles);
  });

  test('changed dependencies sort by code-unit (name, version)', async () => {
    const client = clientWithFiles([
      {
        filename: 'bun.lock',
        patch: [
          '+    "a_pkg": ["a_pkg@1.0.0", "", {}, "sha512-a"],',
          '+    "a-pkg": ["a-pkg@1.0.0", "", {}, "sha512-b"],',
          '+    "apkg": ["apkg@1.0.0", "", {}, "sha512-c"],',
        ].join('\n'),
      },
    ]);

    const changes = await extractChanges(client);

    expect(changes.changedDependencies?.map((dependency) => dependency.name)).toEqual([
      'a-pkg',
      'a_pkg',
      'apkg',
    ]);
  });
});

describe('the module never reaches for localeCompare', () => {
  test('changed-files.ts sorts with compareCodeUnits only', async () => {
    const source = await Bun.file(new URL('../src/changed-files.ts', import.meta.url)).text();
    const code = source.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/\/\/[^\n]*/gu, '');
    expect(code).not.toContain('localeCompare');
    expect(code).toContain('compareCodeUnits');
  });
});
