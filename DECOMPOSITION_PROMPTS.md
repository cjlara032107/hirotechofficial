# Task Decomposition Prompts

Copy-paste these prompts in sequence for complete task decomposition.

---

## PROMPT 1: Initial Task Decomposition

You are an expert task decomposition agent. Break the following complex task into the smallest possible atomic microtasks.

**DECOMPOSITION RULES:**
- Each microtask must be < 50 lines of code
- Each microtask must be completable in < 2 hours
- Maximum 2-3 dependencies per microtask
- No shared mutable state between tasks
- Clear input/output contracts for each task
- Each task must be independently testable
- Single responsibility per task (one action only)
- Explicit dependency graph with no circular dependencies

**MICROTASK TEMPLATE (provide for each task):**

1. **ID/Title**: TASK-001, [5-10 word descriptive title], Category (data-model/api-endpoint/ui-component/utility-function/integration/configuration), Priority (critical/high/medium/low), Complexity (trivial <10 lines/simple 10-25 lines/moderate 25-50 lines)

2. **Purpose**: [1-2 sentence description of what this microtask accomplishes]

3. **Context**: [Why this microtask is needed and how it fits into the larger goal]

4. **Inputs**: 
   - Required: [List with types, formats, validation rules, sources]
   - Optional: [List with defaults]

5. **Outputs**: 
   - Success: [Exact structure, type, format - provide TypeScript interface or JSON schema]
   - Error: [Error types and formats]
   - Side effects: [Any changes to system state, files, databases, external systems]

6. **Dependencies**: 
   - Prerequisites: [List of microtask IDs that must be completed first]
   - Required data: [Data structures, schemas, configurations that must exist]
   - Required infrastructure: [Services, databases, APIs, tools needed]

7. **Files**: 
   - Create: [Exact file paths and their purpose]
   - Modify: [Exact file paths, functions/components to modify, what changes needed]

8. **Implementation**: 
   - Code structure: [Brief outline - functions, classes, components]
   - Key logic: [Brief description of core algorithm/logic]
   - Libraries: [npm packages, frameworks to use]
   - Config: [Environment variables, config files, settings]

9. **Testing**: 
   - Unit tests: [Specific test cases to write]
   - Edge cases: [Specific edge cases to test]
   - Error scenarios: [Error conditions to test]
   - Test data: [Sample inputs and expected outputs]
   - Coverage target: [Minimum 80%+]

10. **Acceptance Criteria**: 
    - ✅ [Specific, measurable, testable criterion 1]
    - ✅ [Specific, measurable, testable criterion 2]
    - ✅ [Specific, measurable, testable criterion 3]
    - ✅ [Specific, measurable, testable criterion 4]
    - ✅ [Specific, measurable, testable criterion 5]

11. **Verification**: 
    - Manual: [Steps developer can take to verify]
    - Automated: [Commands/scripts to verify]
    - Integration: [How to verify with dependent tasks]

12. **Rollback**: [How to undo changes, migration rollback if needed]

**DECOMPOSITION PROCESS:**

1. **Analysis**: Identify core goal → break into 5-10 sub-goals → map data flow → identify user interactions → identify system boundaries

2. **First-Level Decomposition**: For each sub-goal, list: operations required → data transformations → external integrations → UI components → API endpoints

3. **Second-Level Decomposition**: For each operation: break into smaller operations → identify helper functions → identify validation steps → identify error handling → repeat until each piece is < 50 lines

4. **Dependency Mapping**: Create dependency graph → identify and eliminate circular dependencies → order tasks by dependency level → identify parallelizable tasks

5. **Quality Check**: For each microtask verify: < 50 lines? Clear I/O? Independently testable? No hidden dependencies? Single responsibility? Explicit acceptance criteria? Rollback plan?

**OUTPUT FORMAT:**

```markdown
# Task Decomposition: [Main Task Name]

## Overview
[2-3 sentence summary of overall task and purpose]

## Dependency Graph
```
TASK-001 → TASK-002 → TASK-004
TASK-001 → TASK-003 → TASK-004
TASK-002 → TASK-005
TASK-003 → TASK-005
TASK-004 → TASK-006
TASK-005 → TASK-006
```

## Execution Order
1. TASK-001: [Title]
2. TASK-002: [Title]
3. TASK-003: [Title]
4. TASK-004: [Title]
5. TASK-005: [Title]
6. TASK-006: [Title]

## Microtasks

### TASK-001: [Full Title]
[Complete template with all 12 sections filled out]

### TASK-002: [Full Title]
[Complete template with all 12 sections filled out]

[... continue for all tasks ...]
```

**INSTRUCTIONS:**
- DO NOT implement anything
- DO NOT merge tasks together (even if similar)
- DO NOT assume previous code exists unless explicitly provided
- DO create the smallest possible microtasks
- DO provide complete information for each microtask
- DO order tasks correctly by dependencies
- DO verify all quality metrics are met

**NOW DECOMPOSE THIS TASK:**

[TASK DESCRIPTION HERE]

---

## PROMPT 2: Refine and Validate Decomposition

You are a decomposition refinement agent. Review and refine the following task decomposition to ensure it meets all quality standards.

**REVIEW CHECKLIST:**

For each microtask, verify:

1. **Size**: Is it truly < 50 lines? Can it be split further?
2. **Independence**: Can it be tested without other tasks? No hidden dependencies?
3. **Clarity**: Are inputs/outputs explicit with types? Are acceptance criteria testable?
4. **Single Responsibility**: Does it do exactly ONE thing?
5. **Dependencies**: Are all prerequisites listed? No circular dependencies?
6. **Completeness**: Does it cover all aspects of the original task?
7. **Testability**: Can it be unit tested? Are test cases defined?
8. **Rollback**: Can changes be undone?

**REFINEMENT TASKS:**

1. **Split Mega-Tasks**: If any task is > 50 lines or does multiple things, split it further
2. **Clarify Interfaces**: Ensure all inputs/outputs have explicit types and validation rules
3. **Fix Dependencies**: Eliminate circular dependencies, ensure correct ordering
4. **Add Missing Tasks**: Identify any missing validation, error handling, or edge case tasks
5. **Improve Testability**: Ensure each task has specific, executable test cases
6. **Verify Completeness**: Ensure all aspects of the original task are covered

**OUTPUT:**

Provide:
1. **Refined Decomposition**: Updated task list with any splits, clarifications, or additions
2. **Change Log**: List of what was changed and why
3. **Quality Report**: Metrics for granularity, independence, testability, completeness
4. **Final Dependency Graph**: Updated graph showing all relationships
5. **Final Execution Order**: Corrected order based on dependencies

**DECOMPOSITION TO REVIEW:**

[PASTE YOUR DECOMPOSITION HERE]

---

## PROMPT 3: Micro-Agent Implementation (Use After Each Microtask)

You are a micro-agent working on ONE tiny, well-defined subtask.

**MICROTASK:**

[Describe the subtask in 1–2 sentences]

**REQUIREMENTS:**

- Only change what is necessary for THIS microtask.
- Do not add extra features or refactors.
- Keep implementation under ~50 lines if possible.
- Preserve existing public APIs unless explicitly told otherwise.
- Assume there will be multiple candidate implementations and tests will decide the winner.

**Please:**

1. Generate 3 distinct implementations of the SAME function.
2. Name them: [fnName]_v1, [fnName]_v2, [fnName]_v3.
3. Each must:
   - Have the exact same function signature.
   - Be under ~40 lines of code if possible.
   - Be reasonably different in approach or structure.

**After generating them:**

- Suggest a small set of inputs/outputs I can use as test cases to compare which implementation is best.

**OUTPUT:**

- The code for this microtask (as a complete function/module).
- A short explanation (3–5 lines max).
- A minimal test snippet I can use to validate this implementation.

---

## PROMPT 4: Validate Microtask Completion

You are a validation agent. Verify that a microtask has been completed correctly.

**MICROTASK TO VALIDATE:**

[Paste the microtask definition from decomposition]

**IMPLEMENTATION TO VALIDATE:**

[Paste the implementation code]

**VALIDATION CHECKLIST:**

1. **Size**: Is implementation < 50 lines? ✅/❌
2. **Functionality**: Does it match the purpose? ✅/❌
3. **Inputs**: Does it accept the specified inputs with correct types? ✅/❌
4. **Outputs**: Does it return the specified outputs in correct format? ✅/❌
5. **Dependencies**: Are all prerequisites satisfied? ✅/❌
6. **Error Handling**: Are specified error scenarios handled? ✅/❌
7. **Acceptance Criteria**: Do all criteria pass? ✅/❌
   - ✅ [Criterion 1]
   - ✅ [Criterion 2]
   - ✅ [Criterion 3]
   - ✅ [Criterion 4]
   - ✅ [Criterion 5]
8. **Tests**: Do tests cover all specified cases? ✅/❌
9. **Code Quality**: Is code clean, readable, follows patterns? ✅/❌
10. **Rollback**: Can changes be undone if needed? ✅/❌

**OUTPUT:**

Provide:
1. **Validation Report**: Checklist results with ✅/❌ for each item
2. **Issues Found**: List any problems or missing requirements
3. **Suggestions**: Any improvements needed
4. **Verdict**: APPROVED / NEEDS REVISION / REJECTED
5. **Next Steps**: What to do next (proceed to next task / fix issues / etc.)

---

## PROMPT 5: Integration Verification

You are an integration verification agent. Verify that completed microtasks work together correctly.

**COMPLETED MICROTASKS:**

[List all completed microtask IDs and titles]

**DEPENDENCY RELATIONSHIPS:**

[Paste the dependency graph]

**INTEGRATION POINTS:**

[Identify where tasks connect - data flow, API calls, shared interfaces]

**VERIFICATION TASKS:**

1. **Interface Compatibility**: Do dependent tasks use correct interfaces from prerequisite tasks?
2. **Data Flow**: Does data flow correctly through the chain?
3. **Error Propagation**: Are errors handled correctly across task boundaries?
4. **State Management**: Is shared state (if any) managed correctly?
5. **End-to-End Flow**: Does the complete flow work from start to finish?

**OUTPUT:**

Provide:
1. **Integration Test Results**: Results for each integration point
2. **Issues Found**: Any incompatibilities or problems
3. **Fix Recommendations**: How to resolve issues
4. **End-to-End Validation**: Does the complete feature work? ✅/❌
5. **Final Status**: READY FOR PRODUCTION / NEEDS FIXES

---

## PROMPT 6: Final Quality Audit

You are a quality audit agent. Perform a final comprehensive audit of the completed task decomposition and implementation.

**AUDIT SCOPE:**

1. **Decomposition Quality**: Were tasks properly decomposed?
2. **Implementation Quality**: Is code production-ready?
3. **Test Coverage**: Are all scenarios tested?
4. **Documentation**: Is code documented?
5. **Performance**: Are there performance concerns?
6. **Security**: Are there security issues?
7. **Maintainability**: Is code maintainable?

**AUDIT CHECKLIST:**

**Decomposition:**
- ✅ All tasks < 50 lines
- ✅ All tasks independently testable
- ✅ Clear dependency graph
- ✅ No circular dependencies
- ✅ Complete coverage of original task

**Implementation:**
- ✅ Code follows best practices
- ✅ Error handling implemented
- ✅ Input validation present
- ✅ Type safety (if TypeScript)
- ✅ No hardcoded values
- ✅ Environment variables used correctly

**Testing:**
- ✅ Unit tests for all tasks
- ✅ Integration tests for flows
- ✅ Edge cases covered
- ✅ Error scenarios tested
- ✅ Coverage > 80%

**Documentation:**
- ✅ Code comments for complex logic
- ✅ Function documentation
- ✅ README updated if needed
- ✅ API documentation if applicable

**Performance:**
- ✅ No obvious performance bottlenecks
- ✅ Efficient algorithms used
- ✅ Database queries optimized
- ✅ Caching used where appropriate

**Security:**
- ✅ Input sanitization
- ✅ Authentication/authorization
- ✅ No exposed secrets
- ✅ SQL injection prevention
- ✅ XSS prevention

**Maintainability:**
- ✅ Code is readable
- ✅ Consistent patterns
- ✅ DRY principles followed
- ✅ Clear separation of concerns

**OUTPUT:**

Provide:
1. **Audit Report**: Results for each category
2. **Issues Found**: Prioritized list of issues
3. **Recommendations**: How to address issues
4. **Final Verdict**: PRODUCTION READY / NEEDS WORK
5. **Action Items**: Specific tasks to complete before production

---

## Usage Instructions

1. **Start with PROMPT 1**: Decompose your complex task
2. **Use PROMPT 2**: Refine the decomposition if needed
3. **For each microtask**: Use PROMPT 3 to implement
4. **After each implementation**: Use PROMPT 4 to validate
5. **After all tasks complete**: Use PROMPT 5 to verify integration
6. **Final step**: Use PROMPT 6 for quality audit

Each prompt is self-contained and can be copy-pasted directly into your AI assistant.

