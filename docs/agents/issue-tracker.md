# Issue tracker: GitHub

Issues and specifications for this repository live in GitHub Issues in
`zimondeng/data-desensitization-center`. Use the `gh` CLI.

## Conventions

- Create an issue: `gh issue create --title "..." --body "..."`.
  For multiline bodies, write the exact content to a file and use `--body-file`.
- Read an issue: `gh issue view <number> --json number,title,body,labels,comments`.
- List issues: `gh issue list --state open --json number,title,body,labels,comments`
  with appropriate `--label` and `--state` filters.
- Add a sub-issue: `gh issue create --parent <parent> ...` or
  `gh issue edit <parent> --add-sub-issue <child>` (`gh` 2.94+).
  If sub-issues are unavailable, add `Part of #<parent>` to the child body.
- Record blockers using GitHub issue dependencies:
  `gh issue create --blocked-by <number>,<number> ...` or
  `gh issue edit <child> --add-blocked-by <blocker>` (`gh` 2.94+).
  If dependencies are unavailable, add `Blocked by: #<number>, #<number>`
  to the child body. A ticket is unblocked when every blocker is closed.
- Count open blockers:
  `gh api repos/{owner}/{repo}/issues/<number> --jq .issue_dependencies_summary.blocked_by`.
- Comment: `gh issue comment <number> --body "..."`.
- Apply or remove a label:
  `gh issue edit <number> --add-label "..."` or `--remove-label "..."`.
- Close an issue: post the explanation with `gh issue comment`, then run
  `gh issue close <number>`.

Before creating an issue, verify the target with
`gh repo view --json nameWithOwner`; use this repository, not an upstream
repository belonging to someone else.

## Pull requests as a triage surface

**PRs as a request surface: no.**

When set to `yes`, triage external pull requests using the corresponding
`gh pr` commands and the same labels and states as issues.

## Skill operations

- When a skill says to publish to the issue tracker, create a GitHub issue.
- When a skill says to fetch a relevant ticket, read the GitHub issue.
- For wayfinding, use one issue labelled `wayfinder:map` as the map and
  link child tickets as sub-issues. Use `wayfinder:<type>` labels for
  ticket types. If sub-issues are unavailable, add the children to a task
  list in the map and put `Part of #<map>` in each child body.
- Claim a wayfinding ticket with `gh issue edit <number> --add-assignee @me`.
  Resolve it by commenting with the result, closing it, and adding a context
  pointer to the map's decisions.
