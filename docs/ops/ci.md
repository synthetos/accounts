# CI and mutation testing

Owner decision, 2026-11-16: run incremental mutation testing on pushes, retain a weekly full run, and keep the 90% floor. The local lead gate remains full.

## Pushes and pull requests

The existing `accounts-ci` verify job runs `pnpm mutation:quick`. It restores `reports/stryker-incremental.json` and its input fingerprint from an immutable, branch-keyed GitHub Actions cache; a branch miss falls back to main. Each key also includes the runner OS, run ID and attempt, so completed runs can publish fresh reports instead of trying to overwrite an immutable cache entry. Only main saves reports, keeping pull-request results out of the trusted main cache. The mutation step still blocks attestation and deployment on failure. Other checks, deployment credentials, and protected deployment jobs are unchanged.

On a warm, compatible cache, Stryker diffs mutated source against the report and reuses unchanged results. A missing report or fingerprint is a full run. The JSON report and each identity boundary (`auth-core`, `idp`, and Worker) must still meet 90%, without rounding; a high score elsewhere cannot mask a weak boundary. Completed below-floor reports may be cached, but the mutation step still fails. A failed or unresolved run does not publish a reusable input fingerprint.

This repository uses Stryker's **command runner with coverage off**. It cannot report individual tests or their coverage. Therefore `tools/mutation/context.mjs` inventories the whole repository, including SQL migrations, backup helpers, tests, tooling, manifests, and configuration, plus Node version and platform. It excludes `node_modules`, `dist`, `reports`, and `.git` path segments even if tracked. Any changed, added or removed test/helper, dependency, or other fingerprinted input forces **all mutants** to run. This conservatively retests every potentially affected mutant when tests change, rather than pretending to know which tests cover which mutants. Untracked non-ignored inputs are included for local quick runs. Mutated source files remain Stryker's responsibility and are excluded from this fingerprint.

The fingerprint supplements [Stryker's documented incremental limitations](https://stryker-mutator.io/docs/stryker-js/incremental/); it does not make incremental results equivalent to a full rerun under every environmental or cross-file behavioral change. Weekly and lead full runs remain the authoritative refresh.

## Weekly and manual runs

`accounts-mutation` runs at **23:37 Sunday, America/New_York**, using GitHub's timezone-aware schedule, including daylight-saving adjustments. It runs only on main. Schedule delivery may be delayed by GitHub.

Weekly runs do not restore the report and run `pnpm mutation`, which removes any old incremental report and invokes Stryker with `--incremental --force`: all mutants execute and a fresh reusable report is generated. The workflow uploads the JSON/HTML reports and survivor list, and refreshes the main cache after a complete run, including a complete below-floor result. Infrastructure errors and incomplete results remain failed runs, never a passing score.

To force a full run, open **Actions → accounts-mutation → Run workflow**, select **main**, leave **full** checked, and run it. Clearing **full** requests the same conservative quick mode used by push CI; scheduled runs always force full regardless of that input. This workflow does not deploy.

When any boundary falls below 90, the mutation job stays failed and a separate serialized reporter job opens or updates the single issue titled **Mutation score below 90**. A previously closed issue is reopened. The body includes boundary scores, survivor/uncovered mutant locations, mutators and replacements, and a link to the run's complete report artifact. Very large lists are truncated in the issue to fit GitHub's size limit; the artifact retains all results for 30 days. Reporter/API failures remain visible workflow failures.

Mutation execution has `contents: read`, no secrets, and no issue-write token. Only the separate main-only reporter has `issues: write`; it does not install dependencies or execute tests. Existing Cloudflare credentials are unchanged.

## Local parity

- `pnpm mutation`: full mutation run, ignoring previous results, retaining the 90% boundary checks.
- `pnpm mutation:quick`: reuse a compatible local report; cold cache or changed test/config inputs force full.
- `pnpm check`: the lead's complete local gate, including full mutation.
- `pnpm check:quick`: the same gate sequence with conservative incremental mutation.

Reports and fingerprints stay under ignored `reports/`. Deleting the directory forces the next quick run to be full. Do not bypass the wrapper with a bare incremental Stryker command after editing tests: the command runner itself cannot invalidate results for those changes.

## Expected time saving

The prior full mutation run was approximately two hours for 3,000 mutants. A source-only push that reuses 90% of results would avoid about 108 minutes of mutant execution, leaving roughly 12 minutes plus installation, dry-run and reporting overhead. This is an illustrative estimate, not a measured benchmark or guaranteed speedup. Unchanged source can reuse nearly all results; first runs, test/helper/dependency/config changes, weekly runs and local lead gates save no mutant execution time. The Stryker log reports the actual reused and executed mutant counts.
