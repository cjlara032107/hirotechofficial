# Task Decomposition

Break into atomic microtasks: < 50 lines, < 2 hours, max 2-3 deps. No shared state, clear I/O, testable alone.

## Template (per task)
1. ID/Title: TASK-001, Category, Priority
2. Purpose: 1 sentence
3. Inputs: Types
4. Outputs: Formats
5. Dependencies: Prerequisite IDs
6. Files: Paths
7. Implementation: Code outline
8. Testing: Cases, 80%+ coverage
9. Acceptance: 3-5 ✅ criteria
10. Rollback: How to undo

## Process
1. Analyze: Goal → sub-goals
2. Decompose: Break until < 50 lines
3. Map deps: Graph → order
4. Verify: < 50 lines? Clear I/O? Testable?

## Output
```markdown
# Task: [Name]
## Graph: TASK-001 → TASK-002
## Order: 1. TASK-001, 2. TASK-002...
## Tasks: [Template each]
```

## Rules
- DON'T: Implement, merge, assume code
- DO: Smallest tasks, complete info, correct order

**DECOMPOSE:**
[Task here]
