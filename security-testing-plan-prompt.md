# Post-Security-Review Testing Plan Prompt

Based on the completed security review, generate a focused testing plan for the identified security concerns.

## Initial Input Required
**Human provides**: Target testing time (e.g., "2 hours", "1 day", "30 minutes")

## Requirements

### Testing Plan Structure:
1. **Extract key security questions** from the review findings (recommended 5-10, but adjust based on scope and time target)
2. **Present questions for approval** before proceeding to tests
3. **Generate tests only after question approval**
4. **Present one test at a time** for individual approval

### Test Format (for each approved question):
- **Type**: Automated / Manual / Mixed
- **Scope**: 1-2 sentence description  
- **Method**: Brief approach
- **Finding vs No Finding**: Clear criteria
- **Est. Time**: Individual test time estimate
- **Total Time Check**: Running total vs target

### Interaction Pattern:
```
Target Time: [X hours/minutes]

## Security Questions
[Present questions with brief rationale, prioritized to fit time budget]

**Total estimated time: X hours**
**Review needed**: Approve questions or request changes?

---

## Test 1: [Name]
**Addresses**: Question X
**Type**: [Automated/Manual/Mixed]
**Description**: [1-2 sentences]
**Approach**: [Brief method]
**Success**: [What indicates secure vs vulnerable]
**Est. Time**: [X minutes]
**Running Total**: [X minutes of Y target]

**Approve this test?**
```

## Guidelines
- **Prioritize by impact** - most critical questions first within time budget
- **Scale question count** to fit time target and scope (may be 3 questions for simple changes, 12+ for major features)
- **Track time budget** throughout test generation
- **Focus on practical exploitation**, not theoretical vulnerabilities
- **Only test what's new/changed** based on the security review
- **One test approval at a time** - don't batch them
- **Keep descriptions concise** - avoid verbose explanations
- **Use appropriate severity**: Critical/High/Medium/Low/No Finding based on actual demonstrated risk
  - **Critical**: System compromise, data breach, authentication bypass
  - **High**: Significant security boundary violation
  - **Medium**: Limited security impact or information disclosure
  - **Low**: Minor security concerns or edge cases
  - **No Finding**: Security controls working properly

**Time Management**: If approaching time limit, ask human whether to continue or stop at current test set.

Generate questions first and wait for approval before proceeding to individual test generation.