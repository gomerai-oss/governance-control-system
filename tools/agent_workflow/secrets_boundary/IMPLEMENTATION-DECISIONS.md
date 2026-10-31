# secrets_boundary — implementation decisions

The secrets-safe boundary of the agent pipeline: what a dispatched agent may read (path denials), what enters
its context (context admission) and what a run may publish (output admission). Standard library only, no
network, no file reads: every input is passed in by the caller. There is no `__init__.py`; the package uses
the namespace-package layout and callers import modules directly (`from secrets_boundary import gate`).

## Detector rules (`detector.py`)

Each rule's shape is assembled from string pieces in the source so that no line of a shipped file is itself
secret-shaped (a literal would trip push protection, the release exposure scan and this boundary's own output
check).

| Rule id | Shape | Why |
|---|---|---|
| `known` | a caller-supplied value of 16 or more characters, verbatim | The run's own secrets (tokens, the injected canary) are the values most likely to leak; exact match has no false positives. Shorter values are ignored: they match ordinary text too often. |
| `known-base64` | the known value in standard or URL-safe base64, padded or not, whole or as the characters fixed by the value alone at each of the three byte alignments inside a longer base64 run | Base64 is the commonest way a value is wrapped (HTTP basic auth, JSON blobs, `base64` in a shell). The alignment forms catch a value embedded in a longer encoded payload. |
| `known-hex` | the known value's UTF-8 bytes in lowercase or uppercase hex | Hex dumps and digests-by-mistake. |
| `known-url` | the known value percent-encoded: reserved characters only (space as `%20` or `+`) and every byte, with uppercase and lowercase escapes | Values pasted into URLs and query strings. A form identical to the verbatim value is reported as `known`. |
| `github-token` | `gh` + one of `pousr` + `_` + 36 or more `[A-Za-z0-9]` | GitHub classic, OAuth, user-to-server, server-to-server and refresh tokens: the credentials the pipeline itself holds. |
| `github-pat` | `github_pat_` + 22 or more `[A-Za-z0-9_]` | GitHub fine-grained personal access tokens. |
| `anthropic-key` | `sk-ant-` + 20 or more `[A-Za-z0-9_-]` | Anthropic API keys used by agent runtimes. |
| `openai-key` | `sk-proj-` + 20 or more `[A-Za-z0-9_-]` | OpenAI project keys used by agent runtimes. |
| `aws-access-key` | `AKIA` + exactly 16 `[0-9A-Z]`, not followed by another `[0-9A-Z]` | AWS access key ids. The trailing guard makes "exactly 16" hold inside a longer upper-case run. |
| `google-api-key` | `AIza` + 35 `[0-9A-Za-z_-]` | Google API keys. |
| `slack-token` | `xox` + one of `abprs` + `-` + 10 or more `[A-Za-z0-9-]` | Slack bot, user and app tokens. |
| `private-key-block` | a PEM line `-----BEGIN <words> PRIVATE KEY-----`, `<words>` being zero or more upper-case words | Any PEM private key (RSA, EC, OPENSSH, ENCRYPTED, and PKCS#8 with no word at all). Prose that only says "private key" has no PEM dashes and is not matched. |
| `canary` | `SBX-CANARY-` + 32 lowercase hex | The canary the dispatcher injects into each run (P9); seeing it anywhere proves a leak path. |
| `<pattern>-base64` | any pattern above inside the UTF-8 decoding of a base64 run of 24 or more characters | One level of decoding catches a wrapped token without the cost or false positives of recursive decoding. |

Choices inside the detector:

- **Digest.** `digest` is the first 16 hex characters of the SHA-256 of the secret value matched: the known
  string itself for every `known*` rule (so one value has one digest in all its spellings), the matched text for
  a pattern, and the decoded matched text for a `-base64` pattern. Sixteen hex characters identify a value for
  correlation across records without being usable to recover it.
- **Base64 runs.** A run is `[A-Za-z0-9+/_-]{24,}` with up to two `=`; the URL-safe characters are mapped to the
  standard alphabet before decoding. The run is decoded starting at each of its first four characters, so a
  wrapped token is found even when the run starts with unrelated alphabet characters; each decoding that is
  valid UTF-8 is scanned. A `-base64` finding spans the whole run, so redaction leaves no encoded fragment.
- **Duplicates.** Findings of different rules are all kept, overlapping or not. Of findings with the same rule and
  digest, one lying inside another is dropped (for example the unpadded spelling inside the padded one), and
  exact repeats are kept once.
- **Order.** Findings are sorted by `start`, then `end`, `kind`, `rule` and `digest`, so the result is
  deterministic.

## Path denials (`paths.py`)

| Rule id | Matches | Why |
|---|---|---|
| `env-file` | final component `.env` or `.env.*` | Environment files hold service credentials. `.env.example` is denied too: the rule cannot tell a template from a filled copy. |
| `ssh` | any component `.ssh`; final component starting `id_rsa`, `id_dsa`, `id_ecdsa` or `id_ed25519` | SSH keys and configs. |
| `key-file` | final suffix `.pem`, `.key`, `.p12` or `.pfx` | Private keys and key stores. |
| `netrc` | `.netrc` or `_netrc` | Plain-text login files used by git, curl and pip. |
| `git-credentials` | `.git-credentials` | Git's plain-text credential store. |
| `cloud-credentials` | any component `.aws`, `.azure` or `gcloud` | Cloud CLI credential directories. |
| `gh-config` | `gh/hosts.yml` (parent `gh`, final `hosts.yml`) | The GitHub CLI's token file. |
| `package-auth` | `.npmrc`, `.pypirc`, `.docker/config.json` | Registry tokens. |
| `proc` | an absolute path under `/proc/`, before or after normalising `.` and `..` | Process environments and memory expose a run's secrets. |

The final component is compared case-insensitively and every other component exactly. Rules are tried in the
order above and the first match is returned. `read_denials()` gives the same rules as checkout-relative globs
(`**/.env`, `**/.env.*`, `**/.ssh/**`, `**/id_rsa*`, ..., `**/*.pem`, ..., `**/.docker/config.json`) in that order,
with no entry for `proc`, which is absolute and outside any checkout.

## Gates (`gate.py`)

- **Fail closed.** Each checkpoint wraps its whole body; any exception (including a bad argument type) returns
  `reason="boundary-error"` with `allow=False`, and `text=None` for context admission. A broken boundary never
  admits anything.
- **Redaction format.** `[REDACTED:<rule>:<digest>]`. It shows a reader what was removed and lets a record's
  finding be matched to the place it was removed from, without carrying any of the value. Overlapping spans are
  merged first; a merged span takes the marker of its earliest finding, the longest one on a tie.
- **Context admission** always allows when it completes; `reason` is `redacted` when anything was replaced and
  `clean` otherwise. Text in the input that asks for a secret to be treated as safe changes nothing: the decision
  depends only on what the detector finds.
- **Output admission** refuses the whole output on any finding. Paths are checked in sorted order, then texts by
  sorted label, so `reason` (`<path or label>: <rule>`) names the same first offender for the same input. A denied
  path is recorded as a finding of kind `path` with the path's rule and the digest of the path. File content
  that is not valid UTF-8 is scanned as Latin-1, so ASCII secrets inside binary content are still found.
- **Known limit.** Paths and labels are not themselves scanned: by the plan, `reason` and the record name them,
  so a caller must not use a secret as a path or label.

## Records (`records.py`)

`record(decision, at)` returns `schema` (`secrets-boundary-decision-v1`), `checkpoint`, `allow`, `reason`, `at`
and `findings`, each finding being `kind`, `rule`, `digest` and `location` (the path or label for output,
`context` for context). The redacted text is not recorded: it is input text. `dumps` writes sorted-key compact
JSON.
