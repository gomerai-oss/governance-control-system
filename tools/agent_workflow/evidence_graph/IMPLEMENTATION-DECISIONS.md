# M-EVGRAPH-001 — A2 implementation decisions

**Mission:** M-EVGRAPH-001, round 1
**Built from:** `missions/M-EVGRAPH-001/PLAN.md`. The package imports `mission_router` (`model.in_scope`, `model.parse_manifest`, `router.load_config`, and the path helpers `mission_dir`, `manifest_path`, `verdict_path` and `MAX_ROUNDS_CEILING`) and does not change it.

The code does not amend the plan. Where the plan leaves a choice open, the choice below is recorded so A1, A3 or HITL can reject it.

The package always reads the real repository it is pointed at. It has no inactive, draft, fixture-only or activation switch, and no login is written into it: every identity comes from `mission_router/config.json` (or `--config`).

## Layout

| File | Role |
|---|---|
| `history.py` | Running git (read-only, list argv, `-z`), the shallow-clone and ref checks, the first-parent walk and its landing / hand_merge / direct classification, `Identities` from `load_config`, and `authored_by` |
| `chain.py` | Rules R1–R8 for one landing (`prove`), and what each landing established: approval, plan, builds with their rounds, build merges, reviews, spec links |
| `graph.py` | `walk`, the `evidence-graph-v1` document (`document`, `build_graph`), counts, the canonical form and the digest |
| `__main__.py` | `python3 -m evidence_graph build\|check\|trace` |
| `../tests/test_evidence_graph.py` | V1–V15 as `test_v1_…` to `test_v15_…`, plus R1, missing-ref, usage and package-shape cases |

The layout is the plan's. There is no `__init__.py`: `evidence_graph` is a namespace package, run as `python3 -m evidence_graph` with `tools/agent_workflow` on `PYTHONPATH`.

## Resolutions

1. **Login of a commit.** Git records an author name and email, not a GitHub login. A commit counts as authored by login `X` when its author name equals `X`, or its author email is GitHub's no-reply address for `X` (`X@users.noreply.github.com` or `<id>+X@users.noreply.github.com`). Both comparisons ignore case, as GitHub logins do. The first form covers the router's and the dispatcher's commits (the dispatcher writes `<login>` / `<login>@users.noreply.github.com`), and the second covers merges HITL makes in the web UI under a display name. This is evidence from history alone: an author line is not a signature, and a forged one is not detected here.
2. **Git is read-only by construction.** `Repo._run` refuses any subcommand outside `rev-parse`, `log`, `show`, `diff-tree`, `ls-tree`, `cat-file`. `log` adds `--no-show-signature` so a user's `log.showSignature` cannot add lines to the parsed output. Commit records are read with `-z` and fields separated by `\x1f`, with the subject last.
3. **Paths are exact.** Paths are decoded as UTF-8 with `surrogateescape`, so a name that is not UTF-8 survives unchanged. The canonical JSON is encoded the same way, so such a path is written back as its original bytes. Repositories with UTF-8 names, which is every repository this runs on today, get plain UTF-8 JSON.
4. **A missing file at a commit.** `cat-file blob <sha>:<path>` failing reads as "not there". This is how R2 sees a missing `mission.json`, R4 a missing verdict and the spec step a missing `PLAN.md`.
5. **Findings are per item.** R5, R6 and R7 report one finding per offending file, or per offending merge. R1 reports the wrong author and the wrong parent count separately. R3 reports one finding with the number of approval commits. R4 reports each missing or invalid verdict, each round whose `merge A2 round k` count is not 1, each `reviewed_sha` mismatch, and the `top^1` mismatch. The `top^1` check runs only when round `N`'s verdict parsed, because without it there is no `reviewed_sha` to compare, and the missing verdict is already a finding.
6. **R7 and the approval.** "Other than the approval commit" excludes every commit that has one of R3's two approval forms. When there is exactly one, that is the approval commit. When there are several, R3 already fails, and they are not reported a second time under R7.
7. **Round ceiling.** The landing subject allows any round number. Rounds above `MAX_ROUNDS_CEILING` (10) are an R4 finding, and only rounds `1..10` are read. This keeps a forged subject from making the walk loop without bound.
8. **Verdict parsing for R4** is exactly the plan's: a JSON object with `schema` `mission-verdict-v1`, `mission_id` `ID` and an integer `round` `k`. The review node takes `verdict` and `reviewed_sha` when they are strings, and `null` otherwise. R8 then fails a verdict that is not the expected `FAIL` / `PASS`.
9. **Nodes and edges a failed rule cannot establish.** A landing that fails R1 gets its `landing` node, its `mission` node and `MERGED_AS`, and nothing else. Without a unique approval (R3), there is no `plan` or `approval` node, so there are no `APPROVES`, `IMPLEMENTS` or `SPECIFIES` edges. Build nodes and `PRODUCES` remain. A `build_merge` node exists for each round whose `merge A2 round k` commit is unique. `REVIEWS` (and `FINDS_MISMATCH`) is drawn only when the verdict's `reviewed_sha` is that round's `build_merge`.
10. **Build rounds.** An A2 non-merge commit in the range that is on no `merge A2 round k` second-parent side keeps its `build` node, with `round: null`. It gets no `CORRECTS` edge.
11. **Shared commits and repeated missions.** If two landings reach the same commit, the node from the earliest landing in the walk is kept. If a mission lands more than once, its single `mission` node is `proven` only when every landing is proven, and takes `title`, `approval` and `rounds` from the latest landing. Each landing keeps its own `MERGED_AS` edge.
12. **Digest.** `digest` is the SHA-256 hex of the canonical bytes of the document without `digest`, including the final newline.
13. **Command line.** Argument errors print one line, `python3 -m evidence_graph: <message>`, and exit 2. A config that does not load, a shallow clone, a missing ref and a git failure print one line and exit 2. The shallow-clone line is exactly `shallow clone: full history required`. `build` checks the clone and the ref before it writes, so nothing is written on exit 2. A `trace` path that never changed prints one line on stderr and exits 2. Finding details are folded onto one line in `check`'s output. A `trace` field that a failed rule left unknown (plan, approval, verdict, reviewed sha) prints as `-`.
14. **Tests** build their repositories with plumbing (`read-tree`, `hash-object`, `update-index`, `write-tree`, `commit-tree`, `update-ref`), so every parent is exact. A merge's tree is its second parent's, and each side branch contains the merge's first parent, which is how the router's merges look. Authors are set per commit with `-c user.name=… -c user.email=…`. Dates are fixed, `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` point at an empty file, and every inherited `GIT_*` variable is dropped. This isolation also applies to the direct function calls. No test reads this repository's own history.
