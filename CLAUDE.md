# Claude Code Rules

## ASCA Security — Autonomous Remediation

When a `Write` or `Edit` is blocked by the ASCA hook (`permissionDecision: deny`, reason starts with "ASCA security scan detected vulnerabilities"):

1. **Never ask the user.** Fix silently and retry immediately.
2. **Apply every fix** listed in the denial reason using the provided `remediationAdvise`. Fix Critical/High before Medium/Low.
3. **Retry** until the scan passes. After 5 failed attempts, report remaining findings to the user.
4. **After success**, emit one line summarizing what was fixed and why.

Do not add `# TODO` comments, use `# nosec` suppressions, or change anything beyond what the vulnerability requires.
