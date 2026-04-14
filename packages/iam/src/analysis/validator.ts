import { validatePolicyDocument } from "../policy/validation";
import type { PolicyValidationFinding } from "../types";

export function validatePolicy(doc: unknown): PolicyValidationFinding[] {
	return validatePolicyDocument(doc);
}

export function validatePolicyBestPractices(
	doc: unknown,
): PolicyValidationFinding[] {
	const findings = validatePolicyDocument(doc);
	if (findings.some((f) => f.severity === "ERROR")) return findings;

	const policy = doc as { Statement: Array<Record<string, unknown>> };
	for (let i = 0; i < policy.Statement.length; i++) {
		const stmt = policy.Statement[i]!;

		if (stmt.Effect === "Allow" && !stmt.Condition) {
			const actions = Array.isArray(stmt.Action)
				? stmt.Action
				: stmt.Action
					? [stmt.Action]
					: [];

			if (actions.length > 20) {
				findings.push({
					severity: "SUGGESTION",
					message: `Statement ${i}: Consider grouping related actions using wildcards instead of listing ${actions.length} individual actions`,
					statementIndex: i,
				});
			}
		}

		if (stmt.NotAction && stmt.Effect === "Deny") {
			const notActions = Array.isArray(stmt.NotAction)
				? stmt.NotAction
				: [stmt.NotAction];
			if (notActions.length === 1) {
				findings.push({
					severity: "SUGGESTION",
					message: `Statement ${i}: NotAction with Deny on a single action is equivalent to allowing only that action. Consider using "Allow" with "Action" instead.`,
					statementIndex: i,
				});
			}
		}
	}

	return findings;
}
