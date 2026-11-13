# PR 9437 — manual live CLI evidence

Screenshots supplied by Eder on November 13, 2026, paired without altering their contents. This evidence covers direct CLI invocation, not automated code-agent hooks or a dedicated service account.

## GitHub: close and comment

![Command](github-command.png)
![Closed issue and matching comment](github-result.png)

## GitLab: close with a requested comment

![Command](gitlab-command.png)
![Closed issue](gitlab-result.png)

The screenshot confirms closure; the comment is not visible.

## Jira: New → In Progress → Closed

![In Progress command and success response](jira-progress-command.png)
![Close command with Done resolution and success response](jira-closed-command.png)
![Status and resolution history](jira-history.png)
![Final closed issue](jira-result.png)

The Jira commands include comments, but the screenshots do not show the comment stream. The initial close attempt without required resolution was rejected; supplying Done succeeded.

Open index.html locally for the self-contained evidence page with embedded screenshots.
