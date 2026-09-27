/**
 * Checks on the gate-integrity guard (#137).
 *
 * Four things need proving, and they are different:
 *
 * 1. **The guard fires** on each protected surface. A guard nobody has watched
 *    reject anything is an untested function that happens to live in a test file
 *    (ADR-0016), so every entry in `GATE_SURFACES` carries a case that blocks.
 * 2. **The guard stays silent on ordinary work.** This is the failure mode that
 *    would actually bite: a guard that fires on every pull request gets its label
 *    applied reflexively, and a reflexive acknowledgment is not one.
 * 3. **The guard refuses to pass over an input it could not read.** Its pass
 *    condition is "no gate path in this list", which is indistinguishable from
 *    "the list is empty because the listing failed" unless something separates
 *    them. Those cases are the reason the check is worth anything, so they are
 *    asserted directly rather than left to the shape of the code.
 * 4. **The acknowledgment counts only when an admin or maintainer applied it**
 *    (ADR-0042, #232). Triage can apply a label, so presence alone let anyone
 *    granted triage acknowledge their own gate change (#219). Each way the
 *    attribution can be wrong — history out of order, a removal after the
 *    application, a relabel by someone with a lesser role, a lookup that failed
 *    or answered for someone else — is asserted to fail closed.
 *
 * The coverage assertion at the end is deliberate: it fails if a surface is
 * added to `GATE_SURFACES` without a case that observes it blocking, which is
 * clause 2 of ADR-0016 applied to the guard's own growth.
 */

import { describe, expect, test } from 'bun:test';
import {
  ACK_ROLES,
  CODEOWNERS_LOCATIONS,
  DEFAULT_ACK_LABEL,
  DOCUMENTED_UNPROTECTED_ROUTES,
  GATE_SURFACES,
  attributeAcknowledgment,
  changedPaths,
  classifyGateChanges,
  displayPath,
  flattenPages,
  formatBlock,
  formatReport,
  isGitHubLogin,
  labelEventsFor,
  normalizePath,
  parseArgs,
  pluck,
  surfaceOf,
  verifyAcknowledger,
  type AckVerdict,
  type RunContext,
  type Trigger,
} from './check-gate-integrity.ts';

const ACK = DEFAULT_ACK_LABEL;

/** No acknowledgment on the pull request — the verdict most path cases run under. */
const ABSENT: AckVerdict = { kind: 'absent' };

/**
 * An acknowledgment that passed every check. For cases whose subject is the path
 * matcher rather than who acknowledged; the attribution itself is exercised end
 * to end through {@link acknowledge} below.
 */
function accepted(actor = 'mbeacom', role: (typeof ACK_ROLES)[number] = 'admin'): AckVerdict {
  return { kind: 'accepted', actor, role };
}

const T1 = '2026-09-25T01:00:00Z';
const T2 = '2026-09-25T02:00:00Z';
const T3 = '2026-09-25T03:00:00Z';

/** One entry of `GET repos/{repo}/issues/{n}/events`, in the shape the live API returns. */
function rawEvent({
  id,
  at,
  event = 'labeled',
  actor = 'mbeacom',
  label = ACK,
}: {
  id: number;
  at: string;
  event?: 'labeled' | 'unlabeled';
  actor?: string | null;
  label?: string;
}): Record<string, unknown> {
  return {
    id,
    event,
    created_at: at,
    actor: actor === null ? null : { login: actor, type: 'User' },
    label: { name: label, color: 'fbca04' },
    performed_via_github_app: null,
  };
}

/** Events that carry no `label` at all, as the live history interleaves them. */
const NOISE: ReadonlyArray<Record<string, unknown>> = [
  { id: 11, event: 'referenced', created_at: T1, actor: { login: 'mbeacom' }, commit_id: 'abc' },
  { id: 12, event: 'subscribed', created_at: T2, actor: { login: 'contributor' } },
  { id: 13, event: 'cross-referenced', created_at: T3, actor: { login: 'someone' } },
];

/** `user.permissions` as the collaborator-permission endpoint reports it, per role. */
const FLAGS = {
  admin: { admin: true, maintain: true, push: true, triage: true, pull: true },
  maintain: { admin: false, maintain: true, push: true, triage: true, pull: true },
  write: { admin: false, maintain: false, push: true, triage: true, pull: true },
  triage: { admin: false, maintain: false, push: false, triage: true, pull: true },
  read: { admin: false, maintain: false, push: false, triage: false, pull: true },
  none: { admin: false, maintain: false, push: false, triage: false, pull: false },
} as const;

/** A `GET repos/{repo}/collaborators/{login}/permission` response, as probed live. */
function permission(
  login: string,
  role: string,
  flags: Readonly<Record<string, boolean>> = FLAGS[role as keyof typeof FLAGS] ?? FLAGS.none,
): Record<string, unknown> {
  return {
    permission: role === '' ? 'none' : role,
    role_name: role,
    user: { login, permissions: flags },
  };
}

/** The whole pipeline the CLI runs, from raw API payloads to a verdict. */
function acknowledge(
  labels: readonly string[],
  events: unknown,
  lookup: unknown,
  trigger?: Trigger,
  dismissedThisRun = false,
): AckVerdict {
  const attribution = attributeAcknowledgment(
    labels,
    labelEventsFor(flattenPages(events), ACK),
    ACK,
  );
  const run: RunContext = { dismissedThisRun, ...(trigger === undefined ? {} : { trigger }) };
  return verifyAcknowledger(attribution, lookup, run, ACK);
}

/** The flags the trusted workflow always passes in check mode. */
const CHECK_ARGS = [
  '--files',
  'pr-files.json',
  '--labels',
  'pr-labels.json',
  '--label-events',
  'pr-label-events.json',
  '--ack-permission',
  'ack-permission.json',
  '--dismissed-this-run',
  'false',
];

/** One changed path per protected surface, in the shape a real pull request produces. */
const BLOCKING_CASES: ReadonlyArray<{ path: string; pattern: string }> = [
  { path: '.github/workflows/ci.yml', pattern: '.github/workflows/' },
  { path: '.github/workflows/trusted-gates.yml', pattern: '.github/workflows/' },
  { path: '.github/actions/setup/action.yml', pattern: '.github/actions/' },
  { path: 'scripts/check-dco.ts', pattern: 'scripts/' },
  { path: 'packages/ci/dist/index.js', pattern: 'packages/ci/' },
  { path: 'action.yml', pattern: 'action.yml' },
  { path: 'CODEOWNERS', pattern: 'CODEOWNERS' },
  { path: '.github/CODEOWNERS', pattern: '.github/CODEOWNERS' },
  { path: 'docs/CODEOWNERS', pattern: 'docs/CODEOWNERS' },
];

/** Paths an ordinary change touches. None of these may block. */
const ORDINARY_PATHS = [
  'packages/core/src/graph/build.ts',
  'packages/cli/src/index.ts',
  'docs/adr/0035-execute-the-gates.md',
  'README.md',
  'package.json',
  'bun.lock',
  'site/src/content/docs/cli.md',
  'packages/adapters/spec-kit/extension.yml',
  // Near misses, on purpose: a prefix match on a *string* rather than a path
  // boundary would swallow these, and they are legitimate files.
  'packages/cli-extras/src/index.ts',
  'docs/scripts-overview.md',
  'CODEOWNERS.md',
];

describe('the guard fires on every protected surface', () => {
  for (const { path, pattern } of BLOCKING_CASES) {
    test(`${path} blocks without the acknowledgment`, () => {
      const report = classifyGateChanges([path], ABSENT);
      expect(report.verdict).toBe('blocked');
      expect(report.changes).toHaveLength(1);
      expect(report.changes[0]?.path).toBe(path);
      expect(report.changes[0]?.surface.pattern).toBe(pattern);
    });
  }

  test('one gate path among many ordinary ones still blocks', () => {
    const report = classifyGateChanges([...ORDINARY_PATHS, 'scripts/check-dco.ts'], ABSENT);
    expect(report.verdict).toBe('blocked');
    // The specific observed value, not just the count: a report naming the wrong
    // path would satisfy `changes.length === 1` and tell the reader nothing.
    expect(report.changes.map((change) => change.path)).toEqual(['scripts/check-dco.ts']);
    expect(report.examined).toBe(ORDINARY_PATHS.length + 1);
  });

  test('the block names the path, the reason, and how to acknowledge it', () => {
    const text = formatBlock(classifyGateChanges(['.github/workflows/ci.yml'], ABSENT));
    expect(text).toContain('.github/workflows/ci.yml');
    expect(text).toContain('defines which checks run');
    expect(text).toContain(DEFAULT_ACK_LABEL);
    expect(text).toContain('gh pr edit');
  });

  test('matching is case-insensitive, which can only add a match', () => {
    expect(surfaceOf('Scripts/Check-Dco.ts')?.pattern).toBe('scripts/');
    expect(surfaceOf('.GitHub/Workflows/ci.yml')?.pattern).toBe('.github/workflows/');
    expect(surfaceOf('codeowners')?.pattern).toBe('CODEOWNERS');
  });

  test('a leading ./ and backslashes normalize rather than escaping the match', () => {
    expect(normalizePath('./scripts/x.ts')).toBe('scripts/x.ts');
    expect(surfaceOf('./scripts/check-dco.ts')?.pattern).toBe('scripts/');
    expect(surfaceOf('scripts\\check-dco.ts')?.pattern).toBe('scripts/');
  });
});

describe('the guard stays silent on ordinary work', () => {
  test('an ordinary change is clean, and says how much it looked at', () => {
    const report = classifyGateChanges(ORDINARY_PATHS, ABSENT);
    expect(report.verdict).toBe('clean');
    expect(report.changes).toEqual([]);
    expect(report.examined).toBe(ORDINARY_PATHS.length);
    expect(formatReport(report)).toContain(`examined ${ORDINARY_PATHS.length} changed path(s)`);
  });

  for (const path of ORDINARY_PATHS) {
    test(`${path} does not match a gate surface`, () => {
      expect(surfaceOf(path)).toBeUndefined();
    });
  }

  test('a prefix matches at a path boundary, not as a bare substring', () => {
    // `packages/cli-extras/` starts with neither `packages/ci/` nor `scripts/`,
    // but a naive `includes` or a prefix without the trailing slash would claim
    // otherwise — and a guard that fires here would be silenced by deletion.
    expect(surfaceOf('packages/cli-extras/src/index.ts')).toBeUndefined();
    expect(surfaceOf('packages/cifs/x.ts')).toBeUndefined();
  });
});

describe('the acknowledgment', () => {
  // An acknowledgment that satisfies every rule: present, last applied by
  // @mbeacom, whose role here is admin.
  const history = [rawEvent({ id: 1, at: T1 })];
  const lookup = permission('mbeacom', 'admin');

  test('a gate change passes once an admin has applied the label', () => {
    const ack = acknowledge([DEFAULT_ACK_LABEL], history, lookup);
    const report = classifyGateChanges(['scripts/check-dco.ts'], ack);
    expect(report.verdict).toBe('acknowledged');
    expect(report.acknowledged).toBe(true);
    // Still reported, not swallowed: acknowledged is not the same as clean, and
    // the log has to say which one happened.
    expect(report.changes).toHaveLength(1);
    expect(formatReport(report)).toContain('acknowledged by the');
  });

  test('label matching ignores case and surrounding whitespace', () => {
    const ack = acknowledge(['  Gate-Change-Acknowledged '], history, lookup);
    expect(classifyGateChanges(['scripts/x.ts'], ack).verdict).toBe('acknowledged');
  });

  test('an unrelated label does not acknowledge anything', () => {
    const ack = acknowledge(['enhancement', 'github_actions'], history, lookup);
    expect(ack).toEqual({ kind: 'absent' });
    expect(classifyGateChanges(['scripts/x.ts'], ack).verdict).toBe('blocked');
  });

  test('a label that merely contains the token does not acknowledge', () => {
    const ack = acknowledge(['not-gate-change-acknowledged'], history, lookup);
    expect(classifyGateChanges(['scripts/x.ts'], ack).verdict).toBe('blocked');
  });

  test('the acknowledgment does not make an ordinary change report as acknowledged', () => {
    // The verdict has to distinguish "nothing matched" from "something matched
    // and was waved through", or a stale label would rewrite the log of a clean run.
    expect(classifyGateChanges(['README.md'], accepted()).verdict).toBe('clean');
  });
});

describe('who applied the acknowledgment is read from the history, in order', () => {
  test('no label means absent, whatever the history says', () => {
    const events = labelEventsFor([rawEvent({ id: 1, at: T1 })], ACK);
    expect(attributeAcknowledgment([], events, ACK)).toEqual({ kind: 'absent' });
    expect(attributeAcknowledgment(['enhancement'], events, ACK)).toEqual({ kind: 'absent' });
  });

  test('a present label with no recorded application is unattributed', () => {
    expect(attributeAcknowledgment([ACK], [], ACK).kind).toBe('unattributed');
    // Other events are not a history of this label.
    expect(attributeAcknowledgment([ACK], labelEventsFor(NOISE, ACK), ACK).kind).toBe(
      'unattributed',
    );
  });

  test('a latest removal while the label is present is unattributed', () => {
    // The live labels say present, the history says removed: one of them is
    // stale, and the application before the removal is not a safe fallback.
    const events = labelEventsFor(
      [rawEvent({ id: 1, at: T1 }), rawEvent({ id: 2, at: T2, event: 'unlabeled' })],
      ACK,
    );
    const attribution = attributeAcknowledgment([ACK], events, ACK);
    expect(attribution.kind).toBe('unattributed');
  });

  test('the latest application by a valid login is attributed to it', () => {
    const events = labelEventsFor([...NOISE, rawEvent({ id: 1, at: T1 })], ACK);
    expect(attributeAcknowledgment([ACK], events, ACK)).toEqual({
      kind: 'attributed',
      actor: 'mbeacom',
    });
  });

  test('the history is sorted rather than trusted in API order', () => {
    // Newest first. Taking the last element as "latest" would credit the
    // contributor's earlier application instead of the admin's later one.
    const newestFirst = [
      rawEvent({ id: 3, at: T3, actor: 'mbeacom' }),
      rawEvent({ id: 2, at: T2, event: 'unlabeled', actor: 'contributor' }),
      rawEvent({ id: 1, at: T1, actor: 'contributor' }),
    ];
    expect(attributeAcknowledgment([ACK], labelEventsFor(newestFirst, ACK), ACK)).toEqual({
      kind: 'attributed',
      actor: 'mbeacom',
    });
    // And the reverse: the last element is an application, the latest is a removal.
    const removalFirst = [
      rawEvent({ id: 2, at: T2, event: 'unlabeled' }),
      rawEvent({ id: 1, at: T1 }),
    ];
    expect(attributeAcknowledgment([ACK], labelEventsFor(removalFirst, ACK), ACK).kind).toBe(
      'unattributed',
    );
  });

  test('the input history is not reordered in place', () => {
    const events = labelEventsFor(
      [rawEvent({ id: 2, at: T2 }), rawEvent({ id: 1, at: T1 })],
      ACK,
    );
    attributeAcknowledgment([ACK], events, ACK);
    expect(events.map((event) => event.id)).toEqual([2, 1]);
  });

  test('a tie on created_at is broken by id, not by position', () => {
    for (const order of [
      [rawEvent({ id: 21, at: T1, actor: 'mbeacom' }), rawEvent({ id: 20, at: T1, actor: 'contributor' })],
      [rawEvent({ id: 20, at: T1, actor: 'contributor' }), rawEvent({ id: 21, at: T1, actor: 'mbeacom' })],
    ]) {
      expect(attributeAcknowledgment([ACK], labelEventsFor(order, ACK), ACK)).toEqual({
        kind: 'attributed',
        actor: 'mbeacom',
      });
    }
  });

  test('another label’s events are ignored', () => {
    const events = labelEventsFor(
      [
        rawEvent({ id: 1, at: T1, actor: 'mbeacom' }),
        rawEvent({ id: 2, at: T2, actor: 'contributor', label: 'enhancement' }),
        rawEvent({ id: 3, at: T3, event: 'unlabeled', actor: 'contributor', label: 'bug' }),
      ],
      ACK,
    );
    expect(events.map((event) => event.id)).toEqual([1]);
    expect(attributeAcknowledgment([ACK], events, ACK)).toEqual({
      kind: 'attributed',
      actor: 'mbeacom',
    });
  });

  test('a null-label event that is the latest is unattributed — it may be this label’s own', () => {
    const events = labelEventsFor(
      [
        rawEvent({ id: 1, at: T1, actor: 'mbeacom' }),
        { ...rawEvent({ id: 2, at: T2, event: 'unlabeled' }), label: null },
      ],
      ACK,
    );
    expect(attributeAcknowledgment([ACK], events, ACK)).toEqual({
      kind: 'unattributed',
      reason:
        "the timeline's latest label event names no label, so it may be this label's removal " +
        'or re-application',
    });
  });

  test('a null-label event before the latest application does not disturb attribution', () => {
    const events = labelEventsFor(
      [
        { ...rawEvent({ id: 1, at: T1, event: 'unlabeled' }), label: null },
        rawEvent({ id: 2, at: T2, actor: 'mbeacom' }),
      ],
      ACK,
    );
    expect(attributeAcknowledgment([ACK], events, ACK)).toEqual({
      kind: 'attributed',
      actor: 'mbeacom',
    });
  });

  test('an absent label is absent regardless of null-label events in the history', () => {
    const events = labelEventsFor(
      [{ ...rawEvent({ id: 1, at: T1, event: 'unlabeled' }), label: null }],
      ACK,
    );
    expect(attributeAcknowledgment([], events, ACK)).toEqual({ kind: 'absent' });
  });

  test('the label in the history is matched ignoring case and whitespace', () => {
    const events = labelEventsFor(
      [rawEvent({ id: 1, at: T1, label: '  Gate-Change-Acknowledged ' })],
      ACK,
    );
    expect(events).toHaveLength(1);
    expect(attributeAcknowledgment([ACK], events, ACK).kind).toBe('attributed');
  });

  test('a deleted ("ghost") actor is unattributed', () => {
    const events = labelEventsFor([rawEvent({ id: 1, at: T1, actor: null })], ACK);
    expect(events[0]?.actor).toBeNull();
    expect(attributeAcknowledgment([ACK], events, ACK).kind).toBe('unattributed');
  });

  test('an actor that is not a GitHub login is unattributed', () => {
    for (const actor of ['-leading-hyphen', 'a'.repeat(40), 'two words', 'x\n::error::forged']) {
      const events = labelEventsFor([rawEvent({ id: 1, at: T1, actor })], ACK);
      expect(attributeAcknowledgment([ACK], events, ACK).kind).toBe('unattributed');
    }
  });
});

describe('isGitHubLogin', () => {
  test('accepts the logins GitHub issues, bots included', () => {
    for (const login of ['mbeacom', 'davesheffer', 'a', 'A1-b2', 'a'.repeat(39), 'github-actions[bot]']) {
      expect(isGitHubLogin(login)).toBe(true);
    }
  });

  test('rejects anything that could reframe a URL or a log line', () => {
    for (const login of [
      '',
      '-x',
      'a'.repeat(40),
      'a b',
      'mbeacom\n',
      'a/b',
      '../admin',
      'x[bot]y',
      '[bot]',
      'a_b',
      'mbeacom?x=1',
    ]) {
      expect(isGitHubLogin(login)).toBe(false);
    }
  });
});

describe('the label history refuses to be partially parsed', () => {
  test('events that carry no label are ignored, not rejected', () => {
    expect(labelEventsFor(NOISE, ACK)).toEqual([]);
  });

  test('the kept event has the shape the verdict reads', () => {
    expect(labelEventsFor([rawEvent({ id: 31801701021, at: T1 })], ACK)).toEqual([
      { id: 31801701021, event: 'labeled', createdAt: T1, actor: 'mbeacom', label: ACK },
    ]);
  });

  // Previously this threw: a "labeled"/"unlabeled" entry with no readable
  // label.name refused the whole list, which made this endpoint's availability
  // a precondition for the check's own availability over a field the verdict
  // does not need to read except when it is this label's own latest event.
  test('a labeled or unlabeled event with no readable label name is kept, with label: null', () => {
    for (const label of [undefined, null, {}, { name: 42 }]) {
      for (const event of ['labeled', 'unlabeled'] as const) {
        const entry = { ...rawEvent({ id: 1, at: T1 }), event, label };
        expect(labelEventsFor([entry], ACK)).toEqual([
          { id: 1, event, createdAt: T1, actor: 'mbeacom', label: null },
        ]);
      }
    }
  });

  test('a null-label entry still throws on a non-integer id or an unparseable created_at', () => {
    for (const id of ['1', 1.5, null, undefined]) {
      const entry = { ...rawEvent({ id: 1, at: T1 }), id, label: null };
      expect(() => labelEventsFor([entry], ACK)).toThrow(/partially-parsed/);
    }
    for (const created_at of ['yesterday', '', 42, null]) {
      const entry = { ...rawEvent({ id: 1, at: T1 }), created_at, label: null };
      expect(() => labelEventsFor([entry], ACK)).toThrow(/partially-parsed/);
    }
  });

  test('a kept event with a non-integer id throws', () => {
    for (const id of ['1', 1.5, null, undefined]) {
      const entry = { ...rawEvent({ id: 1, at: T1 }), id };
      expect(() => labelEventsFor([entry], ACK)).toThrow(/partially-parsed/);
    }
  });

  test('a kept event with an unparseable created_at throws', () => {
    for (const created_at of ['yesterday', '', 42, null]) {
      const entry = { ...rawEvent({ id: 1, at: T1 }), created_at };
      expect(() => labelEventsFor([entry], ACK)).toThrow(/partially-parsed/);
    }
  });

  test('an entry that is not an event object throws', () => {
    for (const entry of [null, 'labeled', 7, { id: 1 }]) {
      expect(() => labelEventsFor([entry], ACK)).toThrow(/partially-parsed/);
    }
  });

  test('paginated (--slurp) and flat shapes read the same history', () => {
    const one = rawEvent({ id: 1, at: T1, actor: 'contributor' });
    const two = rawEvent({ id: 2, at: T2, actor: 'mbeacom' });
    const paged = [[NOISE[0], one], [two, NOISE[1]]];
    const flat = [NOISE[0], one, two, NOISE[1]];
    const fromPaged = labelEventsFor(flattenPages(paged), ACK);
    expect(fromPaged).toEqual(labelEventsFor(flattenPages(flat), ACK));
    expect(fromPaged.map((event) => event.id)).toEqual([1, 2]);
    expect(attributeAcknowledgment([ACK], fromPaged, ACK)).toEqual({
      kind: 'attributed',
      actor: 'mbeacom',
    });
  });
});

describe('only an admin or maintainer acknowledgment counts (ADR-0042)', () => {
  const byAdmin = [rawEvent({ id: 1, at: T1, actor: 'mbeacom' })];

  test('the accepted roles are exactly admin and maintain', () => {
    expect([...ACK_ROLES]).toEqual(['admin', 'maintain']);
  });

  test('an admin application is accepted', () => {
    expect(acknowledge([ACK], byAdmin, permission('mbeacom', 'admin'))).toEqual(accepted());
  });

  test('a maintain application is accepted', () => {
    const history = [rawEvent({ id: 1, at: T1, actor: 'maintainer-1' })];
    expect(acknowledge([ACK], history, permission('maintainer-1', 'maintain'))).toEqual(
      accepted('maintainer-1', 'maintain'),
    );
  });

  test('the login in the lookup is compared ignoring case', () => {
    expect(acknowledge([ACK], byAdmin, permission('MBeacom', 'admin'))).toEqual(accepted());
  });

  for (const role of ['write', 'triage', 'read', '', 'custom-reviewer', 'Admin', 'MAINTAIN']) {
    test(`role ${JSON.stringify(role)} is insufficient`, () => {
      // Custom roles and case variants are rejected rather than folded: the
      // allow-list is the two built-in roles, spelled as GitHub spells them.
      expect(acknowledge([ACK], byAdmin, permission('mbeacom', role, FLAGS.admin))).toEqual({
        kind: 'insufficient',
        actor: 'mbeacom',
        role,
      });
    });
  }

  test('the #219 self-acknowledgment: a triage relabel after a maintainer’s is insufficient', () => {
    // The maintainer applies the label; the author, granted triage, removes it
    // and applies it again. Presence alone would still pass. The latest
    // application is now the author's, and the author's role is what is judged.
    const history = [
      rawEvent({ id: 1, at: T1, actor: 'mbeacom' }),
      rawEvent({ id: 2, at: T2, event: 'unlabeled', actor: 'contributor' }),
      rawEvent({ id: 3, at: T3, actor: 'contributor' }),
    ];
    const ack = acknowledge([ACK], history, permission('contributor', 'triage'));
    expect(ack).toEqual({ kind: 'insufficient', actor: 'contributor', role: 'triage' });
    expect(classifyGateChanges(['.github/workflows/ci.yml'], ack).verdict).toBe('blocked');
  });

  test('a re-application after dismissal counts against whoever re-applied it', () => {
    // A push dismisses the acknowledgment (the workflow removes it as the bot);
    // a write collaborator then puts it back. Cross-acknowledgment between
    // contributors is closed the same way as self-acknowledgment.
    const history = [
      rawEvent({ id: 1, at: T1, actor: 'mbeacom' }),
      rawEvent({ id: 2, at: T2, event: 'unlabeled', actor: 'github-actions[bot]' }),
      rawEvent({ id: 3, at: T3, actor: 'other-contributor' }),
    ];
    expect(acknowledge([ACK], history, permission('other-contributor', 'write'))).toEqual({
      kind: 'insufficient',
      actor: 'other-contributor',
      role: 'write',
    });
  });

  test('a bot never counts', () => {
    const history = [rawEvent({ id: 1, at: T1, actor: 'github-actions[bot]' })];
    // The live shape for a bot: no role, every flag false.
    expect(acknowledge([ACK], history, permission('github-actions[bot]', ''))).toEqual({
      kind: 'insufficient',
      actor: 'github-actions[bot]',
      role: '',
    });
  });

  test('a lookup that answered for a different user is unverified', () => {
    const ack = acknowledge([ACK], byAdmin, permission('someone-else', 'admin'));
    expect(ack.kind).toBe('unverified');
    expect(ack).toMatchObject({ actor: 'mbeacom' });
  });

  test('a failed or missing lookup is unverified', () => {
    for (const lookup of [
      { lookupFailed: true },
      null,
      undefined,
      [],
      'admin',
      {},
      { role_name: 'admin' },
      { role_name: 'admin', user: {} },
      { role_name: 'admin', user: { login: 42 } },
      { user: { login: 'mbeacom', permissions: FLAGS.admin } },
      { role_name: 7, user: { login: 'mbeacom', permissions: FLAGS.admin } },
    ]) {
      expect(acknowledge([ACK], byAdmin, lookup).kind).toBe('unverified');
    }
  });

  test('a lookup that failed is unverified even when it also carries a role', () => {
    // `lookupFailed` is written by the workflow over whatever the failed call
    // left behind; nothing else in the record is trusted once it is set.
    const lookup = { ...permission('mbeacom', 'admin'), lookupFailed: true };
    expect(acknowledge([ACK], byAdmin, lookup).kind).toBe('unverified');
  });

  test('role admin without an admin or maintain flag is unverified, not accepted', () => {
    // Chosen over `insufficient` deliberately. The record contradicts itself, so
    // neither half is believed: `insufficient` would state as fact a role the
    // lookup did not report, and would tell the reader the actor lacks a role the
    // endpoint just said they hold. `unverified` says what is true — the answer
    // could not be trusted — and its remedy, re-running, is the right one.
    for (const flags of [FLAGS.none, FLAGS.write, {}]) {
      expect(acknowledge([ACK], byAdmin, permission('mbeacom', 'admin', flags)).kind).toBe(
        'unverified',
      );
      expect(acknowledge([ACK], byAdmin, permission('mbeacom', 'maintain', flags)).kind).toBe(
        'unverified',
      );
    }
    const noFlags = { role_name: 'admin', user: { login: 'mbeacom' } };
    expect(acknowledge([ACK], byAdmin, noFlags).kind).toBe('unverified');
    // `true` means true: a truthy string is not a flag.
    const stringly = permission('mbeacom', 'admin', {
      admin: 'true',
      maintain: 'yes',
    } as unknown as Record<string, boolean>);
    expect(acknowledge([ACK], byAdmin, stringly).kind).toBe('unverified');
  });

  test('the flag required is the one named by the role, not either of the two (ADR-0042)', () => {
    // The endpoint sets `maintain: true` for every admin regardless, so accepting
    // either flag for either role would let a `role_name` of "admin" ride in on a
    // `maintain` flag that survived a permission change which no longer grants
    // admin — and the reverse would let "maintain" ride in on a stale admin flag.
    expect(
      acknowledge([ACK], byAdmin, permission('mbeacom', 'admin', { admin: false, maintain: true }))
        .kind,
    ).toBe('unverified');
    expect(
      acknowledge(
        [ACK],
        byAdmin,
        permission('mbeacom', 'maintain', { admin: true, maintain: false }),
      ).kind,
    ).toBe('unverified');
    expect(
      acknowledge(
        [ACK],
        byAdmin,
        permission('mbeacom', 'maintain', { admin: false, maintain: true }),
      ),
    ).toEqual(accepted('mbeacom', 'maintain'));
  });

  test('absent and unattributed pass through without consulting the lookup', () => {
    const lookup = permission('mbeacom', 'admin');
    expect(acknowledge([], byAdmin, lookup)).toEqual({ kind: 'absent' });
    expect(acknowledge([ACK], [], lookup).kind).toBe('unattributed');
    const ghost = [rawEvent({ id: 1, at: T1, actor: null })];
    expect(acknowledge([ACK], ghost, lookup).kind).toBe('unattributed');
  });

  test('a hand-built attribution with an invalid login is not trusted', () => {
    const ack = verifyAcknowledger(
      { kind: 'attributed', actor: 'x\n::error::forged' },
      permission('x\n::error::forged', 'admin'),
      { dismissedThisRun: false },
      ACK,
    );
    expect(ack.kind).toBe('unattributed');
  });
});

describe('the triggering event is cross-checked against the history', () => {
  // A `labeled` run knows who applied the label from its own payload. If the
  // history has not caught up, its latest application is someone else's — and
  // judging that earlier actor would credit this application to them.
  const history = [rawEvent({ id: 1, at: T1, actor: 'mbeacom' })];
  const lookup = permission('mbeacom', 'admin');

  test('a labeled run whose sender is not the history’s actor is unverified', () => {
    const trigger: Trigger = { action: 'labeled', label: ACK, sender: 'contributor' };
    const ack = acknowledge([ACK], history, lookup, trigger);
    expect(ack).toMatchObject({ kind: 'unverified', actor: 'mbeacom' });
  });

  test('a labeled run whose sender is the history’s actor proceeds, ignoring case', () => {
    for (const sender of ['mbeacom', 'MBEACOM']) {
      const trigger: Trigger = { action: 'labeled', label: ACK, sender };
      expect(acknowledge([ACK], history, lookup, trigger)).toEqual(accepted());
    }
  });

  test('the trigger label is matched ignoring case and whitespace', () => {
    const trigger: Trigger = {
      action: 'labeled',
      label: ' Gate-Change-Acknowledged ',
      sender: 'contributor',
    };
    expect(acknowledge([ACK], history, lookup, trigger).kind).toBe('unverified');
  });

  test('a run triggered by another label, or by no label, is not cross-checked', () => {
    // `unlabeled` of *this* label is deliberately not in this list — since
    // ADR-0042's dismissal-race rule it is cross-checked too, exercised in
    // "a run triggered by this label's own removal is unverified" above.
    for (const trigger of [
      { action: 'labeled', label: 'enhancement', sender: 'contributor' },
      { action: 'unlabeled', label: 'enhancement', sender: 'contributor' },
      { action: 'synchronize', label: '', sender: 'contributor' },
      { action: 'opened', label: '', sender: 'contributor' },
    ]) {
      expect(acknowledge([ACK], history, lookup, trigger)).toEqual(accepted());
    }
  });

  test('the cross-check does not rescue an insufficient role', () => {
    const trigger: Trigger = { action: 'labeled', label: ACK, sender: 'mbeacom' };
    expect(acknowledge([ACK], history, permission('mbeacom', 'write'), trigger).kind).toBe(
      'insufficient',
    );
  });

  test('a run whose own dismissal step just removed and confirmed the label is unverified', () => {
    // The dismissal step confirmed the label absent; a present label now was
    // applied during this run, after that confirmation. Trusting the history's
    // "latest application" here would credit whoever re-applied it to the wrong
    // run, whether or not this run also carries a triggering label event.
    expect(acknowledge([ACK], history, lookup, undefined, true)).toMatchObject({
      kind: 'unverified',
      actor: 'mbeacom',
    });
    const trigger: Trigger = { action: 'labeled', label: ACK, sender: 'mbeacom' };
    expect(acknowledge([ACK], history, lookup, trigger, true)).toMatchObject({
      kind: 'unverified',
      actor: 'mbeacom',
    });
  });

  test('a run not dismissed this run is judged normally', () => {
    expect(acknowledge([ACK], history, lookup, undefined, false)).toEqual(accepted());
  });

  test('a run triggered by this label’s own removal is unverified — it has since been re-applied', () => {
    for (const label of [ACK, ' Gate-Change-Acknowledged ', ACK.toUpperCase()]) {
      const trigger: Trigger = { action: 'unlabeled', label, sender: 'anyone' };
      expect(acknowledge([ACK], history, lookup, trigger)).toMatchObject({
        kind: 'unverified',
        actor: 'mbeacom',
      });
    }
  });

  test('a run triggered by a different label’s removal proceeds normally', () => {
    const trigger: Trigger = { action: 'unlabeled', label: 'enhancement', sender: 'anyone' };
    expect(acknowledge([ACK], history, lookup, trigger)).toEqual(accepted());
  });
});

describe('the verdict says who acknowledged, and why an acknowledgment did not count', () => {
  const GATE = ['.github/workflows/ci.yml'];
  const NOT_COUNTED: ReadonlyArray<AckVerdict> = [
    { kind: 'absent' },
    { kind: 'unattributed', reason: 'no application of it is recorded' },
    { kind: 'unverified', actor: 'mbeacom', reason: 'the role lookup failed' },
    { kind: 'insufficient', actor: 'contributor', role: 'triage' },
  ];

  test('only an accepted acknowledgment acknowledges', () => {
    for (const ack of NOT_COUNTED) {
      const report = classifyGateChanges(GATE, ack);
      expect(report.verdict).toBe('blocked');
      expect(report.acknowledged).toBe(false);
      expect(report.ack).toEqual(ack);
    }
    const report = classifyGateChanges(GATE, accepted());
    expect(report.verdict).toBe('acknowledged');
    expect(report.ack).toEqual(accepted());
  });

  test('no gate path is clean, whatever the acknowledgment', () => {
    for (const ack of [...NOT_COUNTED, accepted()]) {
      expect(classifyGateChanges(['README.md'], ack).verdict).toBe('clean');
    }
  });

  test('the acknowledged report names who applied it and their role', () => {
    const text = formatReport(classifyGateChanges(GATE, accepted('mbeacom', 'admin')));
    expect(text).toContain(
      `acknowledged by the "${ACK}" label, applied by @mbeacom (admin)`,
    );
    const maintained = formatReport(classifyGateChanges(GATE, accepted('maintainer-1', 'maintain')));
    expect(maintained).toContain('applied by @maintainer-1 (maintain)');
  });

  test('the block states the admin-or-maintain rule, not the triage-or-write one', () => {
    const text = formatBlock(classifyGateChanges(GATE, ABSENT));
    expect(text).toContain('admin or maintain');
    expect(text).toContain('ADR-0042');
    expect(text).not.toContain('triage or write');
    expect(text).toContain('gh pr edit');
  });

  test('an absent label adds no explanation of why it did not count', () => {
    expect(formatBlock(classifyGateChanges(GATE, ABSENT))).not.toContain('does not count');
  });

  test('an unattributed label says why, and to re-apply it', () => {
    const text = formatBlock(
      classifyGateChanges(GATE, { kind: 'unattributed', reason: 'no application of it is recorded' }),
    );
    expect(text).toContain('no application of it is recorded');
    expect(text).toMatch(/remove the label and apply it again/i);
  });

  test('an unverified label names the actor and reason, and says to re-run first', () => {
    const text = formatBlock(
      classifyGateChanges(GATE, { kind: 'unverified', actor: 'mbeacom', reason: 'the role lookup failed' }),
    );
    expect(text).toContain('@mbeacom');
    expect(text).toContain('the role lookup failed');
    expect(text).toMatch(/re-run this job/i);
    expect(text).toMatch(/remove the label and apply it again/i);
  });

  test('an insufficient label names who last applied it and their role', () => {
    const text = formatBlock(
      classifyGateChanges(GATE, { kind: 'insufficient', actor: 'contributor', role: 'triage' }),
    );
    expect(text).toContain('last applied by @contributor, whose role here is triage');
    const bot = formatBlock(
      classifyGateChanges(GATE, { kind: 'insufficient', actor: 'github-actions[bot]', role: '' }),
    );
    expect(bot).toContain('last applied by @github-actions[bot], whose role here is none');
  });

  test('attacker-influenced strings in the explanation cannot forge workflow commands', () => {
    const cases: AckVerdict[] = [
      acknowledge([ACK], [rawEvent({ id: 1, at: T1, actor: 'x\n::error::forged' })], null),
      acknowledge(
        [ACK],
        [rawEvent({ id: 1, at: T1 })],
        permission('mbeacom', 'admin'),
        { action: 'labeled', label: ACK, sender: 'y\n::error::forged' },
      ),
      acknowledge(
        [ACK],
        [rawEvent({ id: 1, at: T1 })],
        permission('mbeacom', 'custom\n::error::forged', FLAGS.admin),
      ),
      acknowledge([ACK], [rawEvent({ id: 1, at: T1 })], {
        ...permission('mbeacom', 'admin'),
        user: { login: 'z\n::error::forged', permissions: FLAGS.admin },
      }),
    ];
    expect(cases.map((ack) => ack.kind)).toEqual([
      'unattributed',
      'unverified',
      'insufficient',
      'unverified',
    ]);
    for (const ack of cases) {
      for (const text of [formatReport(classifyGateChanges(GATE, ack)), formatBlock(classifyGateChanges(GATE, ack))]) {
        const parsed = text.split('\n').filter((line) => line.trimStart().startsWith('::'));
        expect(parsed).toEqual([]);
      }
      expect(formatBlock(classifyGateChanges(GATE, ack))).toContain('\\u000a::error::forged');
    }
  });
});

describe('the guard refuses to pass over an input it could not read', () => {
  test('a non-array payload throws rather than yielding zero paths', () => {
    expect(() => flattenPages({ message: 'Not Found' })).toThrow(/expected a JSON array/);
    expect(() => flattenPages(null)).toThrow(/expected a JSON array/);
  });

  test('paginated and unpaginated shapes both flatten to the same files', () => {
    const paged = [[{ filename: 'a.ts' }], [{ filename: 'b.ts' }]];
    const flat = [{ filename: 'a.ts' }, { filename: 'b.ts' }];
    expect(pluck(flattenPages(paged), 'filename')).toEqual(['a.ts', 'b.ts']);
    expect(pluck(flattenPages(flat), 'filename')).toEqual(['a.ts', 'b.ts']);
  });

  test('an entry missing the field throws rather than silently dropping', () => {
    expect(() => pluck([{ filename: 'a.ts' }, { sha: 'deadbeef' }], 'filename')).toThrow(
      /entry 1 has no string "filename"/,
    );
  });

  test('parseArgs rejects a flag with no value and an unknown flag', () => {
    expect(() => parseArgs(['--files'])).toThrow(/--files needs a value/);
    expect(() => parseArgs(['--files', 'f.json', '--nope'])).toThrow(/unrecognized argument/);
    expect(() => parseArgs(['--labels', 'l.json'])).toThrow(/--files is required/);
  });

  test('parseArgs rejects a non-integer expected count', () => {
    expect(() => parseArgs(['--files', 'f', '--labels', 'l', '--expected-files', 'lots'])).toThrow(
      /non-negative integer/,
    );
  });

  test('an empty expected count fails as missing rather than coercing to zero', () => {
    // `Number('')` is 0 and `Number.isInteger(0)` is true, so an unset
    // `changed_files` would otherwise arrive as a confident "changed nothing".
    for (const empty of ['', '   ']) {
      expect(() =>
        parseArgs(['--files', 'f', '--labels', 'l', '--expected-files', empty]),
      ).toThrow(/the count is missing, not zero/);
    }
    // Zero written deliberately is still a value, and still wrong for a pull
    // request — the empty-list guard is what rejects it, with its own message.
    const options = parseArgs([...CHECK_ARGS, '--expected-files', '0']);
    expect(options.mode === 'check' && options.expectedFiles).toBe(0);
  });

  test('parseArgs accepts the shape the trusted workflow passes', () => {
    const options = parseArgs([
      ...CHECK_ARGS,
      '--expected-files',
      '12',
      '--trigger-action',
      'labeled',
      '--trigger-label',
      ACK,
      '--trigger-sender',
      'mbeacom',
    ]);
    expect(options).toEqual({
      mode: 'check',
      files: 'pr-files.json',
      labels: 'pr-labels.json',
      labelEvents: 'pr-label-events.json',
      ackPermission: 'ack-permission.json',
      expectedFiles: 12,
      ackLabel: DEFAULT_ACK_LABEL,
      trigger: { action: 'labeled', label: ACK, sender: 'mbeacom' },
      dismissedThisRun: false,
    });
  });

  test('--dismissed-this-run is required in check mode', () => {
    expect(() =>
      parseArgs(CHECK_ARGS.slice(0, CHECK_ARGS.length - 2)),
    ).toThrow(/--dismissed-this-run is required/);
  });

  test('--dismissed-this-run rejects anything other than exactly "true" or "false"', () => {
    for (const value of ['', 'TRUE', 'True', '1', '0', 'yes', ' true', 'true ']) {
      const args = [...CHECK_ARGS.slice(0, CHECK_ARGS.length - 1), value];
      expect(() => parseArgs(args)).toThrow(/must be exactly "true" or "false"/);
    }
    expect(parseArgs(CHECK_ARGS).mode).toBe('check');
  });

  test('a repeated flag is rejected, --print-ack-actor included', () => {
    expect(() => parseArgs([...CHECK_ARGS, '--files', 'other.json'])).toThrow(
      /--files was given more than once/,
    );
    expect(() =>
      parseArgs(['--print-ack-actor', '--print-ack-actor', '--labels', 'l', '--label-events', 'e']),
    ).toThrow(/--print-ack-actor was given more than once/);
  });
});

describe('the CLI requires the history and the role, with no presence-only fallback', () => {
  test('check mode requires the label history and the role lookup', () => {
    // A check that fell back to "the label is present" when either was missing
    // would reopen exactly the self-acknowledgment ADR-0042 closes.
    expect(() => parseArgs(['--files', 'f', '--labels', 'l'])).toThrow(
      /--label-events is required/,
    );
    expect(() => parseArgs(['--files', 'f', '--labels', 'l', '--label-events', 'e'])).toThrow(
      /--ack-permission is required/,
    );
    expect(() => parseArgs(['--label-events'])).toThrow(/--label-events needs a value/);
    expect(() => parseArgs(['--ack-permission'])).toThrow(/--ack-permission needs a value/);
  });

  test('without trigger flags, check mode has no trigger', () => {
    const options = parseArgs(CHECK_ARGS);
    expect(options.mode).toBe('check');
    expect(options.mode === 'check' && options.trigger).toBeUndefined();
  });

  test('the trigger flags are all or none', () => {
    const all = [
      '--trigger-action',
      'synchronize',
      '--trigger-label',
      '',
      '--trigger-sender',
      'mbeacom',
    ];
    // Every proper, non-empty subset is rejected.
    for (const omit of [
      ['--trigger-action'],
      ['--trigger-label'],
      ['--trigger-sender'],
      ['--trigger-action', '--trigger-label'],
      ['--trigger-action', '--trigger-sender'],
      ['--trigger-label', '--trigger-sender'],
    ]) {
      const partial: string[] = [];
      for (let i = 0; i < all.length; i += 2) {
        if (!omit.includes(all[i]!)) partial.push(all[i]!, all[i + 1]!);
      }
      expect(() => parseArgs([...CHECK_ARGS, ...partial])).toThrow(/all three|go together/);
    }
  });

  test('an empty trigger label is a value — a push carries no label', () => {
    const options = parseArgs([
      ...CHECK_ARGS,
      '--trigger-action',
      'synchronize',
      '--trigger-label',
      '',
      '--trigger-sender',
      'mbeacom',
    ]);
    expect(options.mode === 'check' && options.trigger).toEqual({
      action: 'synchronize',
      label: '',
      sender: 'mbeacom',
    });
  });

  test('an empty trigger action or sender is missing, not anonymous', () => {
    expect(() =>
      parseArgs([
        ...CHECK_ARGS,
        '--trigger-action',
        '',
        '--trigger-label',
        ACK,
        '--trigger-sender',
        'mbeacom',
      ]),
    ).toThrow(/--trigger-action was empty/);
    expect(() =>
      parseArgs([
        ...CHECK_ARGS,
        '--trigger-action',
        'labeled',
        '--trigger-label',
        ACK,
        '--trigger-sender',
        ' ',
      ]),
    ).toThrow(/--trigger-sender was empty/);
  });

  test('--print-ack-actor takes no value and reads only the labels and their history', () => {
    const options = parseArgs(['--print-ack-actor', '--labels', 'l', '--label-events', 'e']);
    expect(options).toEqual({
      mode: 'print-ack-actor',
      labels: 'l',
      labelEvents: 'e',
      ackLabel: DEFAULT_ACK_LABEL,
    });
    expect(
      parseArgs(['--labels', 'l', '--label-events', 'e', '--print-ack-actor', '--ack-label', 'x']),
    ).toEqual({ mode: 'print-ack-actor', labels: 'l', labelEvents: 'e', ackLabel: 'x' });
  });

  test('--print-ack-actor requires the labels and their history', () => {
    expect(() => parseArgs(['--print-ack-actor', '--label-events', 'e'])).toThrow(
      /--labels is required/,
    );
    expect(() => parseArgs(['--print-ack-actor', '--labels', 'l'])).toThrow(
      /--label-events is required/,
    );
  });

  test('--print-ack-actor refuses the check’s inputs rather than ignoring them', () => {
    const base = ['--print-ack-actor', '--labels', 'l', '--label-events', 'e'];
    for (const extra of [
      ['--files', 'f'],
      ['--ack-permission', 'p'],
      ['--expected-files', '3'],
      ['--dismissed-this-run', 'true'],
      ['--trigger-action', 'labeled', '--trigger-label', ACK, '--trigger-sender', 'mbeacom'],
    ]) {
      expect(() => parseArgs([...base, ...extra])).toThrow(/--print-ack-actor/);
    }
  });
});

describe('a rename cannot carry a gate path out of sight', () => {
  // The guard's one real bypass, found by reading what the GitHub files endpoint
  // actually returns rather than by assuming. A rename reports `filename` as the
  // *new* path only; the old one lives in `previous_filename`. Moving the trusted
  // workflow out of `.github/workflows/` therefore presented a path matching
  // nothing, passed clean, and deleted the gate on merge.
  const renameAway = [
    {
      filename: '.github/wf/trusted-gates.yml',
      previous_filename: '.github/workflows/trusted-gates.yml',
      status: 'renamed',
    },
  ];

  test('the new path alone would have evaded the matcher', () => {
    // Stated explicitly so the case documents what it is defending, and fails
    // loudly if `.github/wf/` ever becomes a protected prefix for other reasons.
    expect(surfaceOf('.github/wf/trusted-gates.yml')).toBeUndefined();
  });

  test('the old path is read too, so the rename blocks', () => {
    const report = classifyGateChanges(changedPaths(renameAway), ABSENT);
    expect(report.verdict).toBe('blocked');
    expect(report.changes.map((change) => change.path)).toEqual([
      '.github/workflows/trusted-gates.yml',
    ]);
  });

  test('a rename *into* a gate path blocks on the new path', () => {
    const renameInto = [
      { filename: 'scripts/check-dco.ts', previous_filename: 'tmp/x.ts', status: 'renamed' },
    ];
    expect(classifyGateChanges(changedPaths(renameInto), ABSENT).verdict).toBe('blocked');
  });

  test('a deletion was never affected — filename is the deleted path', () => {
    const deletion = [{ filename: '.github/workflows/ci.yml', status: 'removed' }];
    expect(classifyGateChanges(changedPaths(deletion), ABSENT).verdict).toBe('blocked');
  });

  test('an ordinary rename outside the gate surface stays clean', () => {
    const ordinary = [
      { filename: 'packages/core/src/b.ts', previous_filename: 'packages/core/src/a.ts' },
    ];
    expect(classifyGateChanges(changedPaths(ordinary), ABSENT).verdict).toBe('clean');
  });

  test('an entry with no previous_filename contributes exactly one path', () => {
    // The count matters: `--expected-files` is compared against the *entry* count,
    // and a normalizer that invented a path per entry would make every ordinary
    // pull request report as truncated.
    expect(changedPaths([{ filename: 'a.ts' }, { filename: 'b.ts' }])).toEqual(['a.ts', 'b.ts']);
    expect(changedPaths([{ filename: 'a.ts', previous_filename: null }])).toEqual(['a.ts']);
  });

  test('a non-string previous_filename throws rather than being ignored', () => {
    expect(() => changedPaths([{ filename: 'a.ts', previous_filename: 42 }])).toThrow(
      /non-string "previous_filename"/,
    );
  });
});

describe('CODEOWNERS is protected at every location GitHub honors', () => {
  // Found in security review, not by the coverage assertion below — which reads
  // GATE_SURFACES and therefore cannot see a surface that was never added. GitHub
  // resolves `.github/CODEOWNERS` *before* the root file, so a pull request that
  // adds one supersedes the protected root file without ever touching it. Asserted
  // against a stated list rather than against the surface list itself.
  for (const location of CODEOWNERS_LOCATIONS) {
    test(`${location} blocks without the acknowledgment`, () => {
      expect(classifyGateChanges([location], ABSENT).verdict).toBe('blocked');
    });
  }

  test('the three locations are the ones GitHub honors, in precedence order', () => {
    expect([...CODEOWNERS_LOCATIONS]).toEqual([
      '.github/CODEOWNERS',
      'CODEOWNERS',
      'docs/CODEOWNERS',
    ]);
  });

  test('every stated location is actually in the surface list', () => {
    const declared = new Set(GATE_SURFACES.map((surface) => surface.pattern));
    expect(CODEOWNERS_LOCATIONS.filter((location) => !declared.has(location))).toEqual([]);
  });

  test('a file merely named like CODEOWNERS elsewhere does not block', () => {
    expect(surfaceOf('packages/core/CODEOWNERS')).toBeUndefined();
    expect(surfaceOf('CODEOWNERS.md')).toBeUndefined();
  });
});

describe('printed paths cannot forge workflow commands', () => {
  // Git permits a newline in a filename and the files endpoint carries it
  // through, so an attacker-chosen path can put `::` at the start of a physical
  // log line inside a privileged job. The runner trims leading whitespace before
  // testing for the prefix, so the output's indentation is not protection.
  const forged = '.github/workflows/a.yml\n::error title=Gate::forged';

  test('a path carrying a newline is escaped, not printed raw', () => {
    const report = classifyGateChanges([forged], ABSENT);
    for (const text of [formatReport(report), formatBlock(report)]) {
      const parsed = text.split('\n').filter((line) => line.trimStart().startsWith('::'));
      expect(parsed).toEqual([]);
      // Escaped rather than dropped: the reader still learns the exact path.
      expect(text).toContain('\\u000a::error title=Gate::forged');
    }
  });

  test('the escaped path still blocks, and names its surface', () => {
    const report = classifyGateChanges([forged], ABSENT);
    expect(report.verdict).toBe('blocked');
    expect(report.changes[0]?.surface.pattern).toBe('.github/workflows/');
  });

  test('an ordinary path is printed unchanged', () => {
    expect(displayPath('scripts/check-dco.ts')).toBe('scripts/check-dco.ts');
  });

  test('carriage returns and zero-width characters are escaped too', () => {
    expect(displayPath('a\rb')).toBe('"a\\u000db"');
    // The case JSON.stringify gets wrong: U+200B is a format character, not a
    // control character, so JSON leaves it exactly as invisible as it found it.
    expect(displayPath('scripts/\u200bx.ts')).toBe('"scripts/\\u200bx.ts"');
    expect(JSON.stringify('scripts/\u200bx.ts')).not.toContain('\\u200b');
  });

  test('a quote or backslash in a path cannot break the rendering', () => {
    expect(displayPath('a"b\\c\nd')).toBe('"a\\"b\\\\c\\u000ad"');
  });
});

describe('the unprotected routes are documented, not claimed away', () => {
  // The first version of this file asserted that every route to neutering a gate
  // ran through a protected path. That was false — `ci.yml` reaches most of its
  // checks through `bun run <name>`, so the root manifest redirects them, and the
  // packages under test are pull-request-controlled too. A false completeness
  // assertion is worse than a documented gap (ADR-0016), so the gap is pinned
  // here: this fails if someone protects one of these without moving the
  // documentation with it, and fails if the list is quietly emptied.
  test('every documented route really is unprotected', () => {
    for (const route of DOCUMENTED_UNPROTECTED_ROUTES) {
      expect(surfaceOf(route.path)).toBeUndefined();
    }
  });

  test('the list names the specific routes that exist today', () => {
    expect(DOCUMENTED_UNPROTECTED_ROUTES.map((route) => route.path)).toEqual([
      'package.json',
      'packages/cli/src/index.ts',
      'packages/core/src/index.ts',
      'bunfig.toml',
      'tsconfig.json',
    ]);
  });

  test('each route says which gates it reaches', () => {
    for (const route of DOCUMENTED_UNPROTECTED_ROUTES) {
      expect(route.reaches.length).toBeGreaterThan(20);
    }
  });

  test('the trusted gates are not reachable from any of them', () => {
    // The property that makes the narrowed claim true rather than an excuse:
    // trusted-gates.yml invokes script paths directly, and both of those paths
    // are protected, so no manifest or package edit can redirect them.
    expect(surfaceOf('scripts/check-dco.ts')).toBeDefined();
    expect(surfaceOf('scripts/check-gate-integrity.ts')).toBeDefined();
    expect(surfaceOf('.github/workflows/trusted-gates.yml')).toBeDefined();
  });
});

describe('the surface list carries its own coverage', () => {
  test('every protected surface has a case that was observed blocking', () => {
    const covered = new Set(BLOCKING_CASES.map((testCase) => testCase.pattern));
    const declared = GATE_SURFACES.map((surface) => surface.pattern);
    // Fails when a surface is added without a negative case, which is ADR-0016
    // clause 2 applied to this guard's own growth rather than to a one-off run.
    expect(declared.filter((pattern) => !covered.has(pattern))).toEqual([]);
  });

  test('every surface states why a change there matters', () => {
    for (const surface of GATE_SURFACES) {
      expect(surface.why.length).toBeGreaterThan(0);
    }
  });

  test('this repository really contains each protected surface', () => {
    // A pattern that matches nothing in the tree is a guard watching a door that
    // is not there. Asserted against real paths rather than against the list itself.
    const real = [
      '.github/workflows/ci.yml',
      'scripts/check-gate-integrity.ts',
      'packages/ci/action.yml',
      'action.yml',
      'CODEOWNERS',
    ];
    for (const path of real) expect(surfaceOf(path)).toBeDefined();
  });
});
