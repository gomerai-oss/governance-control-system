# Security policy

## Reporting a vulnerability

Please report security problems privately, never in a public issue, pull request or discussion.

Use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a vulnerability**.
Include what you found, how to reproduce it, and what an attacker could do with it.

We aim to acknowledge a report within 7 days and to agree a disclosure date with you once we understand the problem.
Please do not disclose it publicly before then.

## What is in scope

Anything that lets an agent or an outside contributor get around the pipeline's controls, for example:

- a change reaching `main` without a passed review, or without the approved plan;
- an agent acting under another agent's or a person's identity;
- a mission changing an `AUTHORITY` path (the pipeline's own code, workflows or policy tables);
- a token, key or secret reaching an agent, a log, a pull request or a comment.

## Supported versions

Only the latest release on `main` receives fixes.

## Your own deployment

GCS runs in your repository with your GitHub Apps, keys and settings. Keep App private keys only in the `main`-only
environments described in the README, never give an agent App the Workflows or Administration permission, and require
the `route-handoff-block` check on `main`.
