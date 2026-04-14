import { CONDITION_OPERATORS } from "../constants";
import type { PolicyStatement, PolicyValidationFinding } from "../types";

export function validatePolicyDocument(
	doc: unknown,
): PolicyValidationFinding[] {
	const findings: PolicyValidationFinding[] = [];

	if (!doc || typeof doc !== "object") {
		findings.push({
			severity: "ERROR",
			message: "Policy document must be a valid object",
		});
		return findings;
	}

	const policy = doc as Record<string, unknown>;

	if (!policy.Version || typeof policy.Version !== "string") {
		findings.push({
			severity: "ERROR",
			message: 'Policy document must include a "Version" field',
			field: "Version",
		});
	}

	if (!policy.Statement) {
		findings.push({
			severity: "ERROR",
			message: 'Policy document must include a "Statement" array',
			field: "Statement",
		});
		return findings;
	}

	if (!Array.isArray(policy.Statement)) {
		findings.push({
			severity: "ERROR",
			message: '"Statement" must be an array',
			field: "Statement",
		});
		return findings;
	}

	if (policy.Statement.length === 0) {
		findings.push({
			severity: "ERROR",
			message: '"Statement" array must contain at least one statement',
			field: "Statement",
		});
		return findings;
	}

	for (let i = 0; i < policy.Statement.length; i++) {
		const stmt = policy.Statement[i] as Record<string, unknown>;
		validateStatement(stmt, i, findings);
	}

	return findings;
}

function validateStatement(
	stmt: Record<string, unknown>,
	index: number,
	findings: PolicyValidationFinding[],
): void {
	if (!stmt || typeof stmt !== "object") {
		findings.push({
			severity: "ERROR",
			message: `Statement at index ${index} must be an object`,
			statementIndex: index,
		});
		return;
	}

	if (stmt.Effect !== "Allow" && stmt.Effect !== "Deny") {
		findings.push({
			severity: "ERROR",
			message: `Statement at index ${index} must have Effect "Allow" or "Deny"`,
			statementIndex: index,
			field: "Effect",
		});
	}

	const hasAction = stmt.Action !== undefined;
	const hasNotAction = stmt.NotAction !== undefined;
	if (!hasAction && !hasNotAction) {
		findings.push({
			severity: "ERROR",
			message: `Statement at index ${index} must have "Action" or "NotAction"`,
			statementIndex: index,
		});
	}
	if (hasAction && hasNotAction) {
		findings.push({
			severity: "ERROR",
			message: `Statement at index ${index} cannot have both "Action" and "NotAction"`,
			statementIndex: index,
		});
	}

	const hasResource = stmt.Resource !== undefined;
	const hasNotResource = stmt.NotResource !== undefined;
	if (hasResource && hasNotResource) {
		findings.push({
			severity: "ERROR",
			message: `Statement at index ${index} cannot have both "Resource" and "NotResource"`,
			statementIndex: index,
		});
	}

	const hasPrincipal = stmt.Principal !== undefined;
	const hasNotPrincipal = stmt.NotPrincipal !== undefined;
	if (hasPrincipal && hasNotPrincipal) {
		findings.push({
			severity: "ERROR",
			message: `Statement at index ${index} cannot have both "Principal" and "NotPrincipal"`,
			statementIndex: index,
		});
	}

	if (hasAction) {
		validateActionField(stmt.Action, index, "Action", findings);
	}
	if (hasNotAction) {
		validateActionField(stmt.NotAction, index, "NotAction", findings);
	}

	if (hasResource) {
		validateResourceField(stmt.Resource, index, "Resource", findings);
	}
	if (hasNotResource) {
		validateResourceField(stmt.NotResource, index, "NotResource", findings);
	}

	if (stmt.Condition && typeof stmt.Condition === "object") {
		validateConditions(
			stmt.Condition as Record<string, unknown>,
			index,
			findings,
		);
	}

	checkSecurityWarnings(stmt as unknown as PolicyStatement, index, findings);
}

function validateActionField(
	action: unknown,
	index: number,
	field: string,
	findings: PolicyValidationFinding[],
): void {
	const actions = Array.isArray(action) ? action : [action];
	for (const a of actions) {
		if (typeof a !== "string") {
			findings.push({
				severity: "ERROR",
				message: `Statement at index ${index}: ${field} values must be strings`,
				statementIndex: index,
				field,
			});
			continue;
		}
		if (!a.includes(":") && a !== "*") {
			findings.push({
				severity: "WARNING",
				message: `Statement at index ${index}: Action "${a}" should be in "service:Action" format`,
				statementIndex: index,
				field,
			});
		}
	}
}

function validateResourceField(
	resource: unknown,
	index: number,
	field: string,
	findings: PolicyValidationFinding[],
): void {
	const resources = Array.isArray(resource) ? resource : [resource];
	for (const r of resources) {
		if (typeof r !== "string") {
			findings.push({
				severity: "ERROR",
				message: `Statement at index ${index}: ${field} values must be strings`,
				statementIndex: index,
				field,
			});
			continue;
		}
		if (r !== "*" && !r.startsWith("arn:")) {
			findings.push({
				severity: "WARNING",
				message: `Statement at index ${index}: Resource "${r}" should be an ARN or "*"`,
				statementIndex: index,
				field,
			});
		}
	}
}

function validateConditions(
	conditions: Record<string, unknown>,
	index: number,
	findings: PolicyValidationFinding[],
): void {
	const validOperators = new Set<string>(CONDITION_OPERATORS);

	for (const operator of Object.keys(conditions)) {
		let baseOp = operator;

		if (baseOp.startsWith("ForAllValues:")) {
			baseOp = baseOp.substring("ForAllValues:".length);
		} else if (baseOp.startsWith("ForAnyValue:")) {
			baseOp = baseOp.substring("ForAnyValue:".length);
		}
		if (baseOp.endsWith("IfExists")) {
			baseOp = baseOp.substring(0, baseOp.length - "IfExists".length);
		}

		if (!validOperators.has(baseOp)) {
			findings.push({
				severity: "ERROR",
				message: `Statement at index ${index}: Unknown condition operator "${operator}"`,
				statementIndex: index,
				field: "Condition",
			});
		}
	}
}

function checkSecurityWarnings(
	stmt: PolicyStatement,
	index: number,
	findings: PolicyValidationFinding[],
): void {
	const actions = stmt.Action
		? Array.isArray(stmt.Action)
			? stmt.Action
			: [stmt.Action]
		: [];
	const resources = stmt.Resource
		? Array.isArray(stmt.Resource)
			? stmt.Resource
			: [stmt.Resource]
		: [];

	if (stmt.Effect === "Allow") {
		const hasWildcardAction = actions.some((a) => a === "*");
		const hasWildcardResource = resources.some((r) => r === "*");

		if (hasWildcardAction && hasWildcardResource) {
			findings.push({
				severity: "WARNING",
				message: `Statement at index ${index}: Grants full access (Action: "*", Resource: "*"). Consider restricting scope.`,
				statementIndex: index,
			});
		} else if (hasWildcardAction) {
			findings.push({
				severity: "WARNING",
				message: `Statement at index ${index}: Wildcard Action ("*") grants all actions. Consider restricting.`,
				statementIndex: index,
				field: "Action",
			});
		} else if (hasWildcardResource) {
			findings.push({
				severity: "SUGGESTION",
				message: `Statement at index ${index}: Wildcard Resource ("*") applies to all resources. Consider restricting.`,
				statementIndex: index,
				field: "Resource",
			});
		}

		const sensitiveActions = actions.filter(
			(a) =>
				a.includes("Delete") ||
				a.includes("Create") ||
				a.includes("Put") ||
				a.includes("Update"),
		);
		if (sensitiveActions.length > 0 && !stmt.Condition) {
			findings.push({
				severity: "SUGGESTION",
				message: `Statement at index ${index}: Sensitive actions (${sensitiveActions.join(", ")}) without conditions. Consider adding conditions like IP restrictions or MFA requirements.`,
				statementIndex: index,
			});
		}
	}

	if (stmt.NotAction && stmt.Effect === "Allow") {
		findings.push({
			severity: "WARNING",
			message: `Statement at index ${index}: Using "NotAction" with "Allow" grants access to all actions EXCEPT the listed ones. Ensure this is intended.`,
			statementIndex: index,
		});
	}

	if (stmt.Principal === "*" && stmt.Effect === "Allow") {
		findings.push({
			severity: "WARNING",
			message: `Statement at index ${index}: Principal "*" allows access from any principal. Use conditions to restrict access.`,
			statementIndex: index,
		});
	}
}
