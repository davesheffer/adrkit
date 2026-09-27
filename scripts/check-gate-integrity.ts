/**
 * Fail when a pull request changes the surface that *defines* this repository's
 * CI gates, unless a maintainer has explicitly acknowledged the change.
 *
 * ## Why this exists at all
 *
 * Every gate in `.github/workflows/ci.yml` is executed from the pull request's
 * own checkout, so the pull request can edit both the check and the step that
 * invokes it and still produce a green required status (#137, measured on #98).
 * [ADR-0035](../docs/adr/0035-execute-the-gates-that-certify-a-pull-request-from-the-default-branch.md)
 * moves the checks that matter onto `pull_request_target`, which GitHub executes
 * from the repository's **default branch** — workflow file, referenced actions,
 * and `actions/checkout` commit alike. That closes the "edit the check" half.
 *
 * It does not close the other half. A required status check is matched by
 * *name*, so a pull request that cannot edit the trusted job can still add a
 * job of its own with the same name and let the later result stand. Every route
 * to that shadow runs through a change under `.github/workflows/`, which is what
 * this guard watches.
 *
 * ## What the acknowledgment is, and what it is not
 *
 * The token is a label, applied by hand. Applying a label needs only triage, and
 * triage exists for issue and pull-request management — so the label's mere
 * presence let anyone granted triage acknowledge their own gate change, and any
 * two contributors acknowledge each other's (#219, #232). Since ADR-0042 the label
 * counts only when the timeline's **latest application** of it was by someone
 * whose role on this repository is `admin` or `maintain`. The caller reads the
 * pull request's issue-event history and that actor's collaborator permission
 * from the live API; this script decides, and anything it cannot attribute or
 * verify does not count. An external contributor therefore cannot self-authorize,
 * and neither can a triager; a maintainer can, exactly as a maintainer can
 * already merge.
 *
 * **This is not a claim that gate changes are tamper-proof.** Whoever can merge
 * can label. What changes is the *shape* of the failure: a gate change stops
 * being one diff line among two hundred and becomes an explicit, attributed,
 * timestamped act that blocks the merge until it is performed. ADR-0016 argues
 * that attention is not the constraint, and this guard agrees with it — it does
 * not ask anyone to look harder, it refuses to proceed.
 *
 * ## Dependencies, deliberately none
 *
 * Imports only Node builtins, like `check-dco.ts` and for the same reason: the
 * trusted workflow runs it with no `bun install`, so a broken or hostile
 * dependency graph cannot take the gate-integrity gate down with it. Nothing
 * here reads the repository tree either — the inputs are the pull request's
 * changed-path list, its labels, the label's event history, the role of
 * whoever last applied it, and whether this run's own dismissal step just
 * removed the label and confirmed it absent, all supplied as JSON or a flag by
 * the caller.
 *
 *   bun run scripts/check-gate-integrity.ts \
 *     --files <pr-files.json> --labels <pr-labels.json> \
 *     --label-events <pr-label-events.json> --ack-permission <ack-permission.json> \
 *     --dismissed-this-run <true|false> \
 *     [--expected-files <n>] [--ack-label <name>] \
 *     [--trigger-action <action> --trigger-label <name> --trigger-sender <login>]
 *
 * The role lookup needs a login, and the login comes from the history, so the
 * caller asks this script for it first. `--print-ack-actor` prints the login the
 * history attributes the acknowledgment to — validated, so it is safe to put in
 * a URL — or prints nothing:
 *
 *   bun run scripts/check-gate-integrity.ts --print-ack-actor \
 *     --labels <pr-labels.json> --label-events <pr-label-events.json> [--ack-label <name>]
 */

import { readFileSync } from 'node:fs';

/** The label that, applied by an admin or maintainer, acknowledges a gate change. */
export const DEFAULT_ACK_LABEL = 'gate-change-acknowledged';

/**
 * The roles whose application of the acknowledgment counts (ADR-0042).
 *
 * The two built-in roles above `write`, spelled exactly as the
 * collaborator-permission endpoint spells them in `role_name`. No case folding
 * and no custom roles: a custom role's name says nothing about what it grants,
 * and an allow-list that guessed would be one more thing that can be wrong. A
 * move to an organization with custom roles needs an explicit amendment, not a
 * looser pattern here.
 */
export const ACK_ROLES = ['admin', 'maintain'] as const;

export type AckRole = (typeof ACK_ROLES)[number];

export interface GateSurface {
  /** Matched case-insensitively against a repository-relative POSIX path. */
  readonly pattern: string;
  /** `prefix` matches a directory subtree; `exact` matches one file. */
  readonly kind: 'prefix' | 'exact';
  /** Why a change here can alter what CI certifies. Printed on a block. */
  readonly why: string;
}

/**
 * The surface a change to which can alter what CI certifies.
 *
 * Deliberately narrow. Every entry is here because editing it changes what a
 * gate *does*, not merely what it runs over — a broad list would fire on
 * ordinary work, and a guard that fires constantly is one that gets labelled
 * reflexively, which is the same failure as not having it.
 *
 * `package.json` is a near miss and is left out on purpose. Repointing a
 * `check:*` script is a real neutering vector, but only for the advisory copies
 * in `ci.yml`: the trusted workflow invokes script paths directly rather than
 * through `bun run`, so no manifest edit can redirect it. Including it would put
 * this label on every dependency bump and every version bump, and the protection
 * bought would be over checks that are already not authoritative.
 */
export const GATE_SURFACES: readonly GateSurface[] = [
  {
    pattern: '.github/workflows/',
    kind: 'prefix',
    why: 'defines which checks run, what they invoke, and what they are named',
  },
  {
    pattern: '.github/actions/',
    kind: 'prefix',
    why: 'repository-local actions execute inside those checks',
  },
  {
    pattern: 'scripts/',
    kind: 'prefix',
    why: 'the checks themselves',
  },
  {
    pattern: 'packages/ci/',
    kind: 'prefix',
    why: 'the published governing-decisions and queue Actions, which are gates',
  },
  {
    pattern: 'action.yml',
    kind: 'exact',
    why: 'the Marketplace entry point executes the published governing-decisions Action',
  },
  // All three locations GitHub honors, in its resolution order. Protecting only
  // the root file left the gap that matters: GitHub resolves `.github/CODEOWNERS`
  // *first*, so a pull request that adds one supersedes the protected root file
  // entirely without ever touching it. Found in security review, not by the
  // coverage assertion below — which iterates this list and therefore cannot
  // detect a surface that was never added.
  {
    pattern: '.github/CODEOWNERS',
    kind: 'exact',
    why: 'GitHub resolves this before the root file, so adding it supersedes CODEOWNERS',
  },
  {
    pattern: 'CODEOWNERS',
    kind: 'exact',
    why: 'decides who is asked to review a change to any of the above',
  },
  {
    pattern: 'docs/CODEOWNERS',
    kind: 'exact',
    why: 'the third location GitHub honors, after .github/ and the root',
  },
];

/**
 * The locations GitHub resolves CODEOWNERS from, in its own precedence order.
 *
 * Named separately from {@link GATE_SURFACES} so a test can assert the list is
 * complete against a specific stated set rather than against the surface list
 * itself. A coverage check that reads the thing it is checking cannot see an
 * omission, which is how `.github/CODEOWNERS` was missing in the first place.
 */
export const CODEOWNERS_LOCATIONS = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'] as const;

/**
 * Routes to neutering a gate that this guard **does not** protect.
 *
 * Written down because the first version of this file claimed the opposite — that
 * every route to neutering a gate ran through a protected path — and that was
 * false. A false completeness assertion is worse than a documented gap, which is
 * ADR-0016's whole subject, so the gap is named here and pinned by a test rather
 * than left to a comment that can drift.
 *
 * The distinction that matters:
 *
 * - **The trusted gates are complete.** `trusted-dco` and `gate-integrity` run
 *   from the default branch and invoke script *paths* directly, never
 *   `bun run <name>`, so no manifest edit can redirect them and no package edit
 *   can change what they execute.
 * - **The advisory gates in `ci.yml` are not, and cannot be made so by any path
 *   list.** They run the pull request's own code from its own checkout. Every
 *   entry below is a real way to change what a required context does without
 *   touching a protected path.
 *
 * The remedy for a gate that must be trustworthy is to move it into
 * `trusted-gates.yml`, as the sign-off gate was. Extending this guard's protected
 * list would add friction — the root manifest changes on every weekly Dependabot
 * bump — while still not reaching the code those gates execute.
 */
export const DOCUMENTED_UNPROTECTED_ROUTES: ReadonlyArray<{
  readonly path: string;
  readonly reaches: string;
}> = [
  {
    path: 'package.json',
    reaches:
      'clean-clone-builds runs typecheck, build, lint, release:pack, check:deps, ' +
      'check:freeze-hashes, check:doc-pins, check:stale-refs, check:clause8, ' +
      'check:no-spike-heuristics, check:site-grammar and adr lint through ' +
      '`bun run <name>`; node-smoke, action-dogfood and windows-stale-refs-smoke ' +
      'likewise. Repointing a script redirects all of them.',
  },
  {
    path: 'packages/cli/src/index.ts',
    reaches: 'self-dogfood runs `bun run adr check`, and clean-clone-builds `adr lint`',
  },
  {
    path: 'packages/core/src/index.ts',
    reaches: 'the corpus loader every adr subcommand resolves through',
  },
  {
    path: 'bunfig.toml',
    reaches: 'how every gate in ci.yml is resolved and run',
  },
  {
    path: 'tsconfig.json',
    reaches: 'what typecheck and lint actually check',
  },
];

export interface GateChange {
  readonly path: string;
  readonly surface: GateSurface;
}

export type GateVerdict = 'clean' | 'acknowledged' | 'blocked';

export interface GateIntegrityReport {
  /** Every changed path considered, whether or not it matched. Always reported. */
  readonly examined: number;
  readonly changes: readonly GateChange[];
  readonly acknowledged: boolean;
  readonly ackLabel: string;
  readonly verdict: GateVerdict;
  /**
   * Why the acknowledgment did or did not count. Carried beside `acknowledged`
   * rather than folded into it, so a block can say which rule a present label
   * failed — "remove and re-apply" and "re-run the job" are different remedies,
   * and a reader told neither labels past the block the same way again.
   */
  readonly ack: AckVerdict;
}

/**
 * Pure: normalize a path for matching.
 *
 * Lowercased, because matching case-insensitively can only ever *add* a match.
 * That is the fail-closed direction: `Scripts/check-dco.ts` and
 * `scripts/check-dco.ts` are distinct to git but the same file to a
 * case-insensitive checkout, and a guard that missed one would be silent about
 * the change that mattered.
 *
 * A leading `./` is stripped and backslashes are folded to `/`. GitHub's API
 * emits neither, so both are belt rather than braces — but a normalizer that
 * accepts only the shape it expects fails open on the shape it does not.
 */
export function normalizePath(path: string): string {
  return path.trim().replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();
}

/** Pure: the surface `path` belongs to, or `undefined`. */
export function surfaceOf(path: string): GateSurface | undefined {
  const normalized = normalizePath(path);
  return GATE_SURFACES.find((surface) =>
    surface.kind === 'prefix'
      ? normalized.startsWith(normalizePath(surface.pattern))
      : normalized === normalizePath(surface.pattern),
  );
}

/** Pure: label comparison as used everywhere here — trimmed and case-folded. */
function sameLabel(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/** Pure: `value` as a plain JSON object, or `undefined` for null, arrays, and scalars. */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * Pure: whether `login` has the shape of a GitHub login, app accounts included.
 *
 * The workflow interpolates the login this script prints into an API path and a
 * log line, so what may be printed is decided here rather than escaped there: an
 * alphanumeric first character, then alphanumerics and hyphens to 39 in all, and
 * optionally the `[bot]` suffix GitHub gives app accounts. Nothing that passes can
 * carry a `/`, a `?`, a space, or a newline. The pattern is looser than GitHub's
 * own rules — it admits `a--b` and a trailing hyphen — which is harmless: it only
 * has to exclude what could reframe a URL or a log line, and a login that does not
 * exist fails the lookup and does not count.
 */
export function isGitHubLogin(login: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$/.test(login);
}

/** Pure: a login for the log — `@login` when it is one, escaped when it is not. */
function displayLogin(login: string): string {
  return isGitHubLogin(login) ? `@${login}` : displayPath(login);
}

/** Pure: a `role_name` for the log. The endpoint reports no role as `""`. */
function displayRole(role: string): string {
  return role === '' ? 'none' : displayPath(role);
}

function isAckRole(role: string): role is AckRole {
  return (ACK_ROLES as readonly string[]).includes(role);
}

/** One application or removal of the acknowledgment, as the issue-event history records it. */
export interface LabelEvent {
  readonly id: number;
  readonly event: 'labeled' | 'unlabeled';
  readonly createdAt: string;
  /** `null` when no login is recorded — a deleted account is GitHub's "ghost". */
  readonly actor: string | null;
  /** `null` when the entry names no label, or a non-string one — see below. */
  readonly label: string | null;
}

/**
 * Pure: the acknowledgment's own history, out of `GET repos/{repo}/issues/{n}/events`.
 *
 * The endpoint interleaves every kind of event, and most carry no `label` —
 * `referenced`, `subscribed` and the rest are skipped by their `event`, not by
 * their shape. A `labeled` or `unlabeled` event is the opposite case, and is kept
 * even when its `label.name` is missing or not a string, recorded as `label:
 * null` rather than thrown on. Throwing would make this endpoint's availability
 * a precondition for the check's own availability, over a field the verdict does
 * not need to read except when it is this label's — {@link attributeAcknowledgment}
 * decides what a `null` label means for the latest event, and every earlier one
 * is filtered out by name and never inspected.
 *
 * The fields the verdict orders by get different treatment. An event whose `id`
 * or `created_at` cannot be read cannot be placed in the sequence, and a
 * sequence with a hole in it has no reliable last element — that still throws,
 * as `pluck` does. The actor does not: a missing login is a real state —
 * deleted accounts are reported with a `null` actor — and is recorded as `null`
 * for the verdict to refuse, rather than thrown on.
 */
export function labelEventsFor(
  entries: readonly unknown[],
  ackLabel: string = DEFAULT_ACK_LABEL,
): LabelEvent[] {
  const events: LabelEvent[] = [];
  for (const [index, entry] of entries.entries()) {
    const record = asRecord(entry);
    const event = record?.event;
    if (record === undefined || typeof event !== 'string') {
      throw new Error(
        `entry ${index} is not an issue event with a string "event"; refusing to check a ` +
          `partially-parsed list`,
      );
    }
    if (event !== 'labeled' && event !== 'unlabeled') continue;

    const labelName = asRecord(record.label)?.name;
    const label = typeof labelName === 'string' ? labelName : null;
    if (label !== null && !sameLabel(label, ackLabel)) continue;

    const { id, created_at: createdAt } = record;
    if (typeof id !== 'number' || !Number.isInteger(id)) {
      throw new Error(
        `entry ${index} has no integer "id"; refusing to check a partially-parsed list`,
      );
    }
    if (typeof createdAt !== 'string' || Number.isNaN(Date.parse(createdAt))) {
      throw new Error(
        `entry ${index} has no parseable "created_at"; refusing to check a partially-parsed list`,
      );
    }
    const login = asRecord(record.actor)?.login;
    events.push({
      id,
      event,
      createdAt,
      actor: typeof login === 'string' ? login : null,
      label,
    });
  }
  return events;
}

/** Who the history says last applied the acknowledgment, before their role is known. */
export type Attribution =
  | { readonly kind: 'absent' }
  | { readonly kind: 'unattributed'; readonly reason: string }
  | { readonly kind: 'attributed'; readonly actor: string };

/**
 * Pure: who last applied the acknowledgment, if anyone can be named. Rules 1–3 of
 * ADR-0042.
 *
 * The live labels decide presence, as before; the history decides who. Only the
 * *latest* application is judged, because it is the one the presence reflects. A
 * maintainer's acknowledgment that was removed and put back by someone else is
 * that someone else's acknowledgment now — which is exactly the relabel by which
 * a triager would otherwise inherit a maintainer's (#219).
 *
 * Sorted here rather than trusted in the order the API returned. The endpoint
 * lists oldest first, but that is an observation rather than a contract, and the
 * only failure of trusting it is silent: a wrong actor, judged as though right.
 * Ties on `created_at`, which has one-second resolution, fall to the numeric `id`.
 *
 * A latest `unlabeled` while the label is present is not resolved by stepping
 * back to the application before it. The two reads disagree, one of them is
 * stale, and the earlier application is precisely the one that was taken back.
 *
 * A `labeled`/`unlabeled` event whose own `label` is `null` — {@link labelEventsFor}
 * kept it rather than throwing — is judged the same way: if it is not the
 * *latest* event for this label, it never named this label in the first place as
 * far as this function can tell, and is ignored. If it *is* the latest, it is
 * unattributed rather than silently skipped in favor of the one before it, for
 * the same reason a latest `unlabeled` is not stepped back over: it might be
 * this label's own removal or re-application, arrived with its name missing, and
 * treating the earlier event as "latest" would credit or blame the wrong actor.
 */
export function attributeAcknowledgment(
  labels: readonly string[],
  events: readonly LabelEvent[],
  ackLabel: string = DEFAULT_ACK_LABEL,
): Attribution {
  if (!labels.some((label) => sameLabel(label, ackLabel))) return { kind: 'absent' };

  const timed = events
    .filter((event) => event.label === null || sameLabel(event.label, ackLabel))
    .map((event) => {
      const at = Date.parse(event.createdAt);
      if (Number.isNaN(at)) {
        throw new Error(
          `label event ${event.id} has no parseable time; refusing to order a partial history`,
        );
      }
      return { event, at };
    })
    .sort((a, b) => a.at - b.at || a.event.id - b.event.id);

  const latest = timed[timed.length - 1]?.event;
  if (latest === undefined) {
    return { kind: 'unattributed', reason: 'no application of it is recorded in the timeline' };
  }
  if (latest.label === null) {
    return {
      kind: 'unattributed',
      reason:
        "the timeline's latest label event names no label, so it may be this label's removal " +
        'or re-application',
    };
  }
  if (latest.event === 'unlabeled') {
    return {
      kind: 'unattributed',
      reason:
        "the timeline's latest event for it is a removal, so the timeline and the live " +
        'labels disagree',
    };
  }
  if (latest.actor === null) {
    return {
      kind: 'unattributed',
      reason: 'its latest application has no recorded actor, as when the account was deleted',
    };
  }
  if (!isGitHubLogin(latest.actor)) {
    return {
      kind: 'unattributed',
      reason: `its latest application is attributed to ${displayPath(latest.actor)}, which is not a GitHub login`,
    };
  }
  return { kind: 'attributed', actor: latest.actor };
}

/** The event that started this run, from its payload. */
export interface Trigger {
  readonly action: string;
  /** Empty when the event carries no label, as every non-label event does. */
  readonly label: string;
  readonly sender: string;
}

/**
 * What this run itself did, before the history and the role lookup are judged.
 *
 * Kept apart from {@link Trigger} because the two lag the live state in different
 * ways: the trigger is what *started* this run and can already be stale by the
 * time this step executes; `dismissedThisRun` is what *this run itself* just
 * did, moments before checkout, and is therefore never stale — it is this run
 * asserting a fact about its own recent past.
 */
export interface RunContext {
  readonly trigger?: Trigger;
  /**
   * Whether the dismissal step earlier in this same run deleted the
   * acknowledgment label and then confirmed, by re-reading it, that it was
   * gone. A label present when the history is read below was therefore applied
   * *during this run*, after that confirmation — the run its application
   * started is the one that has to judge it, not this one, which is why this
   * short-circuits to `unverified` ahead of every other check.
   */
  readonly dismissedThisRun: boolean;
}

/**
 * Whether the acknowledgment counts, and if not, why not.
 *
 * `insufficient` is kept apart from `unverified` because their remedies differ. A
 * lesser role is a fact about the actor, and re-running will not change it; a
 * lookup that could not be trusted may succeed next time.
 */
export type AckVerdict =
  | { readonly kind: 'absent' }
  | { readonly kind: 'unattributed'; readonly reason: string }
  | { readonly kind: 'unverified'; readonly actor: string; readonly reason: string }
  | { readonly kind: 'insufficient'; readonly actor: string; readonly role: string }
  | { readonly kind: 'accepted'; readonly actor: string; readonly role: AckRole };

/**
 * Pure: whether the attributed actor's acknowledgment counts. Rules 4–5 of ADR-0042.
 *
 * `permission` is what the caller recorded: the collaborator-permission response,
 * `{ "lookupFailed": true }` when that call failed, or `null` when there was no
 * one to look up. Every field read from it is shape-checked first, and a record
 * that lacks one, answers for a different login, or contradicts itself is
 * `unverified` rather than guessed at. The endpoint's 403 for a token without push
 * access is one real way to arrive here, and it has to read as "could not tell" —
 * never as "fine".
 *
 * The role decides alone only in the refusing direction. `role_name` outside
 * {@link ACK_ROLES} is `insufficient` whatever the flags say; `role_name` inside
 * it must also be backed by the *matching* flag being literally `true` —
 * `admin` needs `permissions.admin`, `maintain` needs `permissions.maintain`,
 * and an admin's `maintain` flag (which the endpoint sets regardless) does not
 * substitute for either — or the record is self-contradictory and is not
 * believed.
 *
 * Two checks run before the role lookup, in this order, both closing windows in
 * which the events endpoint lags this run's own recent past rather than the
 * trigger that started it:
 *
 * 1. `run.dismissedThisRun`: the dismissal step earlier in *this* run deleted the
 *    label and confirmed it gone, so a label present now was applied during this
 *    run, after that confirmation — the run its application started decides it,
 *    not this one.
 * 2. A trigger of `unlabeled` for this label: this run was started by the
 *    label's own removal, and — reached only when the label is present now,
 *    since an absent label already returned `absent` above — it has evidently
 *    been applied again since this run began. Same remedy: the run that
 *    re-application started decides it.
 *
 * The existing `labeled` trigger cross-check runs last, unchanged: a `labeled`
 * run's payload names who applied the label just now, and if the history's
 * latest application is someone else's, the history has not caught up or has
 * already moved on, and judging its actor would credit this application to
 * whoever applied the label before.
 */
export function verifyAcknowledger(
  attribution: Attribution,
  permission: unknown,
  run: RunContext,
  ackLabel: string = DEFAULT_ACK_LABEL,
): AckVerdict {
  if (attribution.kind === 'absent') return { kind: 'absent' };
  if (attribution.kind === 'unattributed') {
    return { kind: 'unattributed', reason: attribution.reason };
  }

  const { actor } = attribution;
  // Re-checked rather than assumed: this function is exported, and an attribution
  // built by hand has not been through `attributeAcknowledgment`.
  if (!isGitHubLogin(actor)) {
    return {
      kind: 'unattributed',
      reason: `it is attributed to ${displayPath(actor)}, which is not a GitHub login`,
    };
  }
  const who = `@${actor}`;
  const unverified = (reason: string): AckVerdict => ({ kind: 'unverified', actor, reason });

  if (run.dismissedThisRun) {
    return unverified(
      'it was applied after this run removed it, so the history read now may not show that ' +
        'application yet; the run it started decides',
    );
  }

  const { trigger } = run;

  if (
    trigger !== undefined &&
    trigger.action === 'unlabeled' &&
    sameLabel(trigger.label, ackLabel)
  ) {
    return unverified(
      'this run was started by its removal and it has been applied again since; the run that ' +
        'application started decides',
    );
  }

  if (
    trigger !== undefined &&
    trigger.action === 'labeled' &&
    sameLabel(trigger.label, ackLabel) &&
    trigger.sender.toLowerCase() !== actor.toLowerCase()
  ) {
    return unverified(
      `this run was started by ${displayLogin(trigger.sender)} applying it, but the ` +
        `timeline's latest application is by ${who}, so the timeline has not caught up ` +
        `with this event or has already moved past it`,
    );
  }

  const record = asRecord(permission);
  if (record === undefined) return unverified(`no role was looked up for ${who}`);
  if ('lookupFailed' in record) return unverified(`the role of ${who} could not be read`);

  const user = asRecord(record.user);
  const login = user?.login;
  if (typeof login !== 'string') {
    return unverified(`the role lookup for ${who} named no user`);
  }
  if (login.toLowerCase() !== actor.toLowerCase()) {
    return unverified(`the role lookup answered for ${displayLogin(login)}, not for ${who}`);
  }

  const role = record.role_name;
  if (typeof role !== 'string') {
    return unverified(`the role lookup for ${who} carried no role_name`);
  }
  if (!isAckRole(role)) return { kind: 'insufficient', actor, role };

  const flags = asRecord(user?.permissions);
  const grantsRole = role === 'admin' ? flags?.admin === true : flags?.maintain === true;
  if (!grantsRole) {
    return unverified(
      `the role lookup names ${who} as ${role} but its "${role}" permission flag is not true`,
    );
  }
  return { kind: 'accepted', actor, role };
}

/**
 * Pure: classify a pull request's changed paths against the gate surface.
 *
 * `blocked` requires *both* that a gate path changed and that the acknowledgment
 * did not count, so the two inputs are reported separately rather than folded
 * into the verdict — a reader has to be able to tell "nothing matched" from
 * "something matched and was acknowledged", and a bare boolean cannot. Only an
 * `accepted` acknowledgment acknowledges; every other kind, a present label
 * included, blocks a gate change exactly as an absent one does.
 */
export function classifyGateChanges(
  paths: readonly string[],
  ack: AckVerdict,
  ackLabel: string = DEFAULT_ACK_LABEL,
): GateIntegrityReport {
  const changes: GateChange[] = [];
  for (const path of paths) {
    const surface = surfaceOf(path);
    if (surface) changes.push({ path, surface });
  }

  const acknowledged = ack.kind === 'accepted';

  const verdict: GateVerdict =
    changes.length === 0 ? 'clean' : acknowledged ? 'acknowledged' : 'blocked';

  return { examined: paths.length, changes, acknowledged, ackLabel, verdict, ack };
}

/**
 * Pure: a path rendered safe to print in a GitHub Actions log.
 *
 * Git permits a newline in a filename and the files endpoint carries it through,
 * so an attacker-chosen path can place `::` at the start of a physical log line
 * inside a privileged job. The runner trims leading whitespace before testing for
 * the workflow-command prefix, so indenting the output is not protection: it
 * would parse `::add-mask::` or `::error::` and let a pull request forge
 * annotations and suppress this guard's own output.
 *
 * `JSON.stringify` escapes every control character and is reversible, so the
 * reader still sees exactly which path tripped the guard. Applied to *every*
 * printed path rather than only suspicious ones, because a rule that decides
 * which paths are dangerous is one more thing that can be wrong.
 */
export function displayPath(path: string): string {
  if (!/[\p{Cc}\p{Cf}]/u.test(path)) return path;
  // Not `JSON.stringify` alone. It escapes control characters below U+0020 but
  // leaves format characters such as U+200B ZERO WIDTH SPACE exactly as they are,
  // so a path carrying one would still print as though it did not — which is the
  // whole failure this function exists to prevent. Escaping every Cc and Cf
  // explicitly makes the invisible visible; the surrounding quotes mark the path
  // as rendered rather than literal.
  const escaped = path
    .replace(/[\\"]/g, (character) => `\\${character}`)
    .replace(
      /[\p{Cc}\p{Cf}]/gu,
      (character) => `\\u${character.codePointAt(0)!.toString(16).padStart(4, '0')}`,
    );
  return `"${escaped}"`;
}

/**
 * Pure: the report as text.
 *
 * States the examined count in every branch, including the clean one. ADR-0016's
 * complementary half: "looked at 41 paths, none under a gate surface" and "could
 * not see the changed paths at all" are the same sentence unless the check says
 * what it looked at, and the second is the one that matters here.
 */
export function formatReport(report: GateIntegrityReport): string {
  const lines = [`check-gate-integrity: examined ${report.examined} changed path(s)`];

  for (const change of report.changes) {
    lines.push(
      `  gate    ${displayPath(change.path)}  — ${change.surface.pattern}: ${change.surface.why}`,
    );
  }

  if (report.verdict === 'clean') {
    lines.push('check-gate-integrity: ok — no path under a gate-defining surface');
  } else if (report.verdict === 'acknowledged') {
    // Who and in what role, not just "acknowledged". The attribution is the whole
    // substance of the acknowledgment since ADR-0042, and a log that omitted it
    // would read the same for a maintainer's label as for anyone else's.
    const by =
      report.ack.kind === 'accepted'
        ? `, applied by ${displayLogin(report.ack.actor)} (${report.ack.role})`
        : '';
    lines.push(
      `check-gate-integrity: ok — ${report.changes.length} gate path(s) changed, ` +
        `acknowledged by the "${report.ackLabel}" label${by}`,
    );
  }

  return lines.join('\n');
}

/**
 * Pure: why a present label did not count, as one line of the block. Empty when
 * the label was absent or counted.
 *
 * Every string here that did not originate in this file is either a validated
 * login or has been through `displayPath`, including the reasons, which were
 * rendered when the verdict was built.
 */
function whyNotCounted(ack: AckVerdict, ackLabel: string): string {
  switch (ack.kind) {
    case 'unattributed':
      return (
        `The "${ackLabel}" label is present but does not count: ${ack.reason}.\n` +
        `Remove the label and apply it again.`
      );
    case 'unverified':
      return (
        `The "${ackLabel}" label was last applied by ${displayLogin(ack.actor)}, but that could ` +
        `not be verified: ${ack.reason}.\n` +
        `Re-run this job; if it still does not count, remove the label and apply it again.`
      );
    case 'insufficient':
      return (
        `The "${ackLabel}" label is present but does not count: it was last applied by ` +
        `${displayLogin(ack.actor)}, whose role here is ${displayRole(ack.role)}.`
      );
    default:
      return '';
  }
}

/** Pure: the failure text for a blocked report. Empty string when not blocked. */
export function formatBlock(report: GateIntegrityReport): string {
  if (report.verdict !== 'blocked') return '';
  // Each path carries its surface's reason. A bare list of filenames tells the
  // reader that something tripped without telling them what the guard thinks the
  // file *is*, which is the difference between acting on the block and labelling
  // past it.
  const listed = report.changes
    .map(
      (change) =>
        `  ${displayPath(change.path)}\n    ${change.surface.pattern} — ${change.surface.why}`,
    )
    .join('\n');
  const whyNot = whyNotCounted(report.ack, report.ackLabel);
  return (
    `${report.changes.length} of ${report.examined} changed path(s) alter the surface that ` +
    `defines this repository's CI gates:\n\n${listed}\n\n` +
    `A change here can alter what every other check certifies, so it needs an explicit\n` +
    `acknowledgment rather than a quiet diff line. A maintainer applies the\n` +
    `"${report.ackLabel}" label to this pull request. It counts only when the latest\n` +
    `application in the timeline was by someone whose role here is admin or maintain\n` +
    `(ADR-0042); triage can apply a label too, so presence alone is not enough.\n\n` +
    (whyNot === '' ? '' : `${whyNot}\n\n`) +
    `  gh pr edit <number> --add-label "${report.ackLabel}"\n\n` +
    `This is not an assertion that the change is correct — it is an assertion that it was\n` +
    `seen. See docs/adr/0035-execute-the-gates-that-certify-a-pull-request-from-the-default-branch.md.`
  );
}

/**
 * Pure: flatten what `gh api --paginate --slurp` produces.
 *
 * `--slurp` wraps each *page* in the outer array, so the shape is `Page[]` and
 * not `File[]`; without `--paginate` it is `File[]` directly. Both are accepted
 * because a script that understands only one of them silently reads zero files
 * from the other, and zero files is this check's pass condition.
 */
export function flattenPages(parsed: unknown): unknown[] {
  if (!Array.isArray(parsed)) {
    throw new Error(`expected a JSON array, got ${parsed === null ? 'null' : typeof parsed}`);
  }
  const flat: unknown[] = [];
  for (const entry of parsed) {
    if (Array.isArray(entry)) flat.push(...entry);
    else flat.push(entry);
  }
  return flat;
}

/** Pure: read a string field off every entry, rejecting an entry that lacks it. */
export function pluck(entries: readonly unknown[], field: string): string[] {
  return entries.map((entry, index) => {
    const value = (entry as Record<string, unknown> | null)?.[field];
    if (typeof value !== 'string') {
      throw new Error(
        `entry ${index} has no string "${field}"; refusing to check a partially-parsed list`,
      );
    }
    return value;
  });
}

/**
 * Pure: every path a changed-file entry touches — its current path and, for a
 * rename, the path it came from.
 *
 * The second half is load-bearing and was the guard's one real bypass. GitHub's
 * files endpoint reports a rename as `filename: <new>` with the old path only in
 * `previous_filename`, so a pull request that moved
 * `.github/workflows/trusted-gates.yml` to `.github/wf/trusted-gates.yml` would
 * present this check with a path matching nothing, pass clean, and delete the
 * trusted gate on merge. A deletion is not affected — `filename` is the deleted
 * path — which is exactly why the gap was easy to miss.
 *
 * Reading both is the fail-closed direction: it can only ever add a path.
 */
export function changedPaths(entries: readonly unknown[]): string[] {
  const paths: string[] = [];
  for (const path of pluck(entries, 'filename')) paths.push(path);
  for (const [index, entry] of entries.entries()) {
    const previous = (entry as Record<string, unknown> | null)?.previous_filename;
    if (previous === undefined || previous === null) continue;
    if (typeof previous !== 'string') {
      throw new Error(
        `entry ${index} has a non-string "previous_filename"; refusing to check a ` +
          `partially-parsed list`,
      );
    }
    paths.push(previous);
  }
  return paths;
}

function readJson(path: string): unknown {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`could not read ${path}, so nothing was examined. ${detail}`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`${path} is not valid JSON, so nothing was examined. ${detail}`);
  }
}

interface CheckOptions {
  readonly mode: 'check';
  files: string;
  labels: string;
  labelEvents: string;
  ackPermission: string;
  expectedFiles?: number;
  ackLabel: string;
  trigger?: Trigger;
  dismissedThisRun: boolean;
}

interface PrintAckActorOptions {
  readonly mode: 'print-ack-actor';
  labels: string;
  labelEvents: string;
  ackLabel: string;
}

export type Options = CheckOptions | PrintAckActorOptions;

/** The flags only the check reads, which `--print-ack-actor` refuses rather than ignores. */
const CHECK_ONLY_FLAGS = [
  '--files',
  '--ack-permission',
  '--expected-files',
  '--trigger-action',
  '--trigger-label',
  '--trigger-sender',
  '--dismissed-this-run',
] as const;

const TRIGGER_FLAGS = ['--trigger-action', '--trigger-label', '--trigger-sender'] as const;

/**
 * Parse the command line.
 *
 * The label history and the role lookup are both **required** in check mode;
 * there is no presence-only fallback. A check that quietly reverted to "the label
 * is present" whenever an input was missing would reopen the self-acknowledgment
 * ADR-0042 closes, and would do it in exactly the runs where something had already
 * gone wrong.
 *
 * The trigger flags come as a set or not at all. Two of three would make the
 * cross-check depend on which one went missing, so a partial set is refused. An
 * empty `--trigger-label` is a value, because every non-label event carries no
 * label; an empty action or sender is not, because every event has both.
 *
 * Every flag, `--print-ack-actor` included, is refused the second time it is
 * given. A repeated flag is a caller bug — a build script that concatenated two
 * argument lists, say — and silently keeping the last (or first) value would
 * mask exactly the kind of mistake that could hand this check a stale input
 * under a name it believes is authoritative.
 */
export function parseArgs(argv: readonly string[]): Options {
  const given = new Set<string>();
  let printAckActor = false;
  const values: Partial<Record<string, string>> = {};
  let ackLabel = DEFAULT_ACK_LABEL;
  let expectedFiles: number | undefined;

  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    switch (flag) {
      case '--print-ack-actor':
        if (given.has(flag)) throw new Error(`${flag} was given more than once`);
        given.add(flag);
        printAckActor = true;
        break;
      case '--files':
      case '--labels':
      case '--label-events':
      case '--ack-permission':
      case '--ack-label':
      case '--trigger-action':
      case '--trigger-label':
      case '--trigger-sender':
      case '--dismissed-this-run':
      case '--expected-files': {
        if (value === undefined) throw new Error(`${flag} needs a value`);
        if (given.has(flag)) throw new Error(`${flag} was given more than once`);
        i += 1;
        given.add(flag);
        if (flag === '--ack-label') ackLabel = value;
        else if (flag === '--trigger-action' && value.trim() === '') {
          throw new Error('--trigger-action was empty; the triggering event is missing, not unnamed');
        } else if (flag === '--trigger-sender' && value.trim() === '') {
          throw new Error('--trigger-sender was empty; the sender is missing, not anonymous');
        } else if (flag === '--dismissed-this-run') {
          if (value !== 'true' && value !== 'false') {
            throw new Error(
              `--dismissed-this-run must be exactly "true" or "false", got "${value}"`,
            );
          }
          values[flag] = value;
        } else if (flag !== '--expected-files') values[flag] = value;
        else {
          // `Number('')` is 0 and `Number.isInteger(0)` is true, so an unset
          // `changed_files` would arrive here as a confident "the pull request
          // changed nothing" rather than as the missing input it is. The empty
          // string is rejected explicitly, because the whole point of this flag is
          // to notice when the count could not be read.
          if (value.trim() === '') {
            throw new Error('--expected-files was empty; the count is missing, not zero');
          }
          const parsed = Number(value);
          if (!Number.isInteger(parsed) || parsed < 0) {
            throw new Error(`--expected-files needs a non-negative integer, got "${value}"`);
          }
          expectedFiles = parsed;
        }
        break;
      }
      default:
        throw new Error(`unrecognized argument "${flag}"`);
    }
  }

  if (printAckActor) {
    // Refused rather than ignored: a caller passing these believes they are being
    // applied, and this mode applies none of them.
    const stray = CHECK_ONLY_FLAGS.find((flag) => given.has(flag));
    if (stray !== undefined) {
      throw new Error(
        `--print-ack-actor reads only --labels, --label-events and --ack-label; ${stray} ` +
          `belongs to the check`,
      );
    }
    const labels = values['--labels'];
    const labelEvents = values['--label-events'];
    if (!labels) throw new Error('--labels is required');
    if (!labelEvents) throw new Error('--label-events is required');
    return { mode: 'print-ack-actor', labels, labelEvents, ackLabel };
  }

  const files = values['--files'];
  const labels = values['--labels'];
  const labelEvents = values['--label-events'];
  const ackPermission = values['--ack-permission'];
  const dismissedThisRunRaw = values['--dismissed-this-run'];
  if (!files) throw new Error('--files is required');
  if (!labels) throw new Error('--labels is required');
  if (!labelEvents) throw new Error('--label-events is required');
  if (!ackPermission) throw new Error('--ack-permission is required');
  if (dismissedThisRunRaw === undefined) throw new Error('--dismissed-this-run is required');
  const dismissedThisRun = dismissedThisRunRaw === 'true';

  const triggerGiven = TRIGGER_FLAGS.filter((flag) => given.has(flag));
  let trigger: Trigger | undefined;
  if (triggerGiven.length === TRIGGER_FLAGS.length) {
    trigger = {
      action: values['--trigger-action'] ?? '',
      label: values['--trigger-label'] ?? '',
      sender: values['--trigger-sender'] ?? '',
    };
  } else if (triggerGiven.length > 0) {
    throw new Error(
      `--trigger-action, --trigger-label and --trigger-sender go together, all three or ` +
        `none; got only ${triggerGiven.join(', ')}`,
    );
  }

  return {
    mode: 'check',
    files,
    labels,
    labelEvents,
    ackPermission,
    ...(expectedFiles === undefined ? {} : { expectedFiles }),
    ackLabel,
    ...(trigger === undefined ? {} : { trigger }),
    dismissedThisRun,
  };
}

/** Read the labels and the label history, and attribute the acknowledgment. */
function readAttribution(labelsPath: string, eventsPath: string, ackLabel: string): Attribution {
  const labels = pluck(flattenPages(readJson(labelsPath)), 'name');
  const events = labelEventsFor(flattenPages(readJson(eventsPath)), ackLabel);
  return attributeAcknowledgment(labels, events, ackLabel);
}

function main(argv: readonly string[]): void {
  const options = parseArgs(argv);

  if (options.mode === 'print-ack-actor') {
    // The caller interpolates this into an API path, so it prints a login that
    // `isGitHubLogin` accepts or nothing at all. Nothing is not a failure: an
    // absent or unattributable label leaves no one to look up, and the check that
    // follows reaches the same verdict from the same files. Only an input that
    // cannot be parsed exits non-zero.
    const attribution = readAttribution(options.labels, options.labelEvents, options.ackLabel);
    if (attribution.kind === 'attributed' && isGitHubLogin(attribution.actor)) {
      console.log(attribution.actor);
    }
    return;
  }

  const entries = flattenPages(readJson(options.files));
  // Two different counts, deliberately kept apart. `entries` is what the pull
  // request changed and is what `changed_files` counts; `paths` can be longer,
  // because a rename contributes both the path it went to and the one it came
  // from. Comparing the wrong one against `--expected-files` would make every
  // renaming pull request fail as "truncated".
  const paths = changedPaths(entries);
  const attribution = readAttribution(options.labels, options.labelEvents, options.ackLabel);
  // May be `null` — the caller's record that there was no one to look up.
  const permission = readJson(options.ackPermission);

  // A pull request always changes at least one file, so an empty list means the
  // listing failed rather than that nothing was touched. Reporting "0 paths, ok"
  // here renders identically to a clean run — the exact fail-quiet shape ADR-0016
  // exists to prevent, and the one that would make this guard useless in the only
  // case it is for.
  if (entries.length === 0) {
    throw new Error(
      'the pull request listed no changed files, which cannot happen. ' +
        'Refusing to report a pass over an empty list.',
    );
  }

  // The files endpoint caps at 3000 entries and says so by truncating, not by
  // erroring. A gate path past the cap would be invisible, so the count the pull
  // request itself reports is compared against the count actually read.
  if (options.expectedFiles !== undefined && options.expectedFiles !== entries.length) {
    throw new Error(
      `the pull request reports ${options.expectedFiles} changed file(s) but ${entries.length} ` +
        `were read; the listing is truncated or stale. Refusing to report a pass over a ` +
        `partial list.`,
    );
  }

  const run: RunContext = {
    dismissedThisRun: options.dismissedThisRun,
    ...(options.trigger === undefined ? {} : { trigger: options.trigger }),
  };
  const ack = verifyAcknowledger(attribution, permission, run, options.ackLabel);
  const report = classifyGateChanges(paths, ack, options.ackLabel);
  console.log(formatReport(report));

  if (report.verdict === 'blocked') throw new Error(formatBlock(report));
}

if (import.meta.main) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`check-gate-integrity: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}
