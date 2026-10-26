# Contributing

Thank you for helping. Bug reports, fixes, documentation and support for more runtimes and forges are all welcome.

## Before you start

- **Bugs:** open an issue with what you did, what you expected and what happened.
- **Security problems:** do not open an issue; follow [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue first so we can agree the approach before you spend time on it. The maintainers
  may decline changes that do not fit the project or that weaken its controls.

## Sign your commits (Developer Certificate of Origin)

Every commit must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
The sign-off certifies that you wrote the change, or otherwise have the right to submit it, under this project's
license (Apache 2.0). Add it with `git commit -s`, which appends a line like:

```
Signed-off-by: Jane Doe <jane@example.com>
```

Use your real name and an email you can be reached at. Pull requests with unsigned commits cannot be merged; to fix
one, run `git rebase --signoff main` and force-push your branch.

## Pull requests

- Keep each pull request to one change, with tests where the code has them.
- Run the tests: `PYTHONPATH=tools/agent_workflow python3 -m unittest discover -s tools/agent_workflow/tests`.
- Standard library only; the pipeline has no third-party dependencies.
- Changes to the specifications in `tools/agent_workflow/specs/` go together with the code they describe.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
