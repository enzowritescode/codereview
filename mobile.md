# Mobile Application Security Review Prompt

Use the following checklist derived from the OWASP Mobile Top 10 (2024 edition) to guide your security review of mobile application code. Evaluate each category carefully to identify vulnerabilities and improve the security posture of the application.

## 1. [M1: Improper Credential Usage](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html)
   - Are credentials (e.g., API keys or user passwords) stored or transmitted securely?
   - Are hardcoded credentials or secrets present in the codebase?
   - Does the app enforce secure credential management practices?

## 2. [M2: Inadequate Supply Chain Security](https://owasp.org/www-project-mobile-top-10/2023-risks/m2-inadequate-supply-chain-security.html)
   - Are third-party libraries and frameworks up-to-date and free from known vulnerabilities?
   - Is the integrity of third-party dependencies verified (e.g., code signing)?
   - Are there security risks associated with external SDKs or cloud services?

## 3. [M3: Insecure Authentication/Authorization](https://owasp.org/www-project-mobile-top-10/2023-risks/m3-insecure-authentication-authorization.html)
   - Are proper authentication mechanisms, such as MFA, implemented?
   - Are access controls enforced to prevent unauthorized access or privilege escalation?
   - Are authentication tokens securely managed and protected against replay attacks?

## 4. [M4: Insufficient Input/Output Validation](https://owasp.org/www-project-mobile-top-10/2023-risks/m4-insufficient-input-output-validation.html)
   - Are inputs validated to prevent injection attacks (e.g., SQL injection, XSS)?
   - Is user-generated content properly sanitized before rendering or storage?
   - Are output encoding practices applied to avoid unintended data exposure?

## 5. [M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)
   - Is all data transmitted securely using protocols like TLS?
   - Is certificate validation enforced to prevent man-in-the-middle attacks?
   - Are sensitive data leaks, such as via unencrypted channels, prevented?

## 6. [M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls.html)
   - Are user data collection and storage processes compliant with privacy regulations (e.g., GDPR, CCPA)?
   - Is sensitive data collection minimized to reduce exposure risks?
   - Are mechanisms like user opt-out or data deletion implemented?

## 7. [M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protection.html)
   - Are mobile app binaries obfuscated to prevent reverse engineering?
   - Are runtime protections in place to detect and defend against tampering?
   - Are debug symbols stripped or mitigated to limit actionable metadata?

## 8. [M8: Security Misconfiguration](https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration.html)
   - Are configurations set to their most secure defaults (e.g., permissions, network settings)?
   - Is error logging devoid of sensitive or exploitable information?
   - Are configurations frequently reviewed to mitigate unintended exposures?

## 9. [M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage.html)
   - Is sensitive data stored securely (e.g., encrypted databases, secure containers)?
   - Are caching mechanisms prevented from storing sensitive information?
   - Is temporary data protected from exposure (e.g., backups, screenshots)?

## 10. [M10: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html)
   - Are strong cryptographic algorithms and key management practices applied?
   - Are weak or outdated cryptographic methods avoided (e.g., MD5, SHA1)?
   - Are all sensitive data securely encrypted in transit and at rest?

---

Use this checklist to identify security issues systematically. Document your findings thoroughly and prioritize remediation based on the severity and exploitability of identified risks.