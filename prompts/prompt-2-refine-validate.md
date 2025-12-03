# PROMPT 2: Refine and Validate Decomposition

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

