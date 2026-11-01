# Security

Report vulnerabilities privately to the repository owner. Never post bearer tokens,
OAuth codes, signing keys or personal records in issues or test evidence.

This repository currently contains foundations only. The Worker returns 503;
GitHub sign-in, OIDC routes and session storage handlers are not implemented.

All authentication and schema changes require independent review. Before enabling
CI deployments, configure native branch protection with two approving reviewers
with write access, required Code Owner review, stale approval dismissal and no
bypass. In-repository CI cannot protect itself from edits in the same PR.
