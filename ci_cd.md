# GitHub Workflow Review Prompt: OWASP Top 10 CI/CD Security Risks

Use this checklist to assess GitHub workflows while adhering to the **OWASP Top 10 CI/CD Security Risks**, ensuring the security of your pipeline.

---

## 1. CICD-SEC-1: Insufficient Flow Control Mechanisms
- Are workflows configured with proper flow control mechanisms (e.g., approvals before critical actions like deployments)?
- Is there a clear separation between build, test, and deployment stages?
- Does the workflow validate inputs to prevent execution of unintended tasks?

---

## 2. CICD-SEC-2: Inadequate Identity and Access Management
- Are all users and services granted only the minimum permissions required for their roles?
- Is the `GITHUB_TOKEN` scoped appropriately (e.g., using the `permissions` block)?
- Are branch protections enabled to limit who can trigger workflows?

---

## 3. CICD-SEC-3: Dependency Chain Abuse
- Are third-party GitHub Actions pinned to specific versions or commit SHAs to protect against supply chain attacks?
- Are dependencies sourced only from trusted repositories and regularly monitored for updates?
- Are workflows protected against malicious dependency injection?

---

## 4. CICD-SEC-4: Poisoned Pipeline Execution (PPE)
- Are workflows configured to restrict execution of untrusted code (e.g., pull requests from forks)?
- Are builds isolated and sandboxed, ensuring external code cannot access sensitive secrets or resources?
- Is code scanned for vulnerabilities or malicious modification before execution?

---

## 5. CICD-SEC-5: Insufficient PBAC (Pipeline-Based Access Controls)
- Are all stages of the workflow governed by appropriate access controls (e.g., sensitive steps require explicit approval)?
- Are role-based access controls (RBAC) applied to limit who can modify or execute workflows?
- Do pipeline permissions prevent tampering or unauthorized execution?

---

## 6. CICD-SEC-6: Insufficient Credential Hygiene
- Are credentials stored securely (e.g., GitHub Secrets) and accessed using `${{ secrets.<SECRET_NAME> }}`?
- Are credentials rotated regularly and revoked immediately after leaks are detected?
- Are secrets restricted to workflows requiring them, without unnecessary sharing?

---

## 7. CICD-SEC-7: Insecure System Configuration
- Is the workflow environment appropriately hardened (e.g., minimizing permissions in Docker containers or VMs)?
- Are insecure configurations (e.g., unrestricted external access) avoided?
- Are commands executed securely to mitigate injection attacks?

---

## 8. CICD-SEC-8: Ungoverned Usage of 3rd Party Services
- Are third-party services (e.g., GitHub Actions or APIs) used responsibly, with proper vetting and validation?
- Is the usage of third-party tools limited to trusted sources, and is their access minimized?
- Are third-party integrations reviewed for compliance with organizational security policies?

---

## 9. CICD-SEC-9: Improper Artifact Integrity Validation
- Are build artifacts validated for integrity (e.g., checksum or signature verification) before use or promotion?
- Are artifacts protected from tampering while in storage or transit?
- Does the workflow ensure that only verified and trusted artifacts are deployed?

---

## 10. CICD-SEC-10: Insufficient Logging and Visibility
- Are workflow runs and logs captured comprehensively for auditing and troubleshooting purposes?
- Do logs exclude sensitive information, such as secrets or tokens?
- Is there a monitoring system in place to detect abnormal activity, failed workflows, or unauthorized changes?

---

## Example Review Feedback Format
1. **Findings:** Detail specific risks or vulnerabilities observed in the workflow, referencing the applicable OWASP CI/CD Security Risk (e.g., CICD-SEC-3).
2. **Severity:** Categorize the severity of each issue (e.g., Low, Medium, High).
3. **Recommendations:** Provide actionable steps to mitigate or resolve each issue.
4. **Overall Risk Assessment:** Summarize the workflow's security posture, noting whether critical risks were identified.

---

Use this prompt as a guide for reviewing GitHub workflows securely while addressing the top CI/CD security risks.