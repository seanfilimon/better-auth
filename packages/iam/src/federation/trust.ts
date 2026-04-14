import { globMatch } from "../policy/arn";
import { evaluateConditionBlock } from "../policy/conditions";
import type { PolicyDocument, PolicyStatement } from "../types";

interface TrustEvaluationParams {
	principalArn: string;
	principalType: string;
	externalId?: string;
}

interface TrustEvaluationResult {
	allowed: boolean;
	matchedStatement?: PolicyStatement;
	reason?: string;
}

export function evaluateTrustPolicy(
	trustPolicy: PolicyDocument,
	params: TrustEvaluationParams,
): TrustEvaluationResult {
	if (!trustPolicy?.Statement || !Array.isArray(trustPolicy.Statement)) {
		return { allowed: false, reason: "Invalid trust policy" };
	}

	for (const stmt of trustPolicy.Statement) {
		if (stmt.Effect !== "Allow") continue;

		if (!matchesTrustPrincipal(stmt, params)) continue;

		if (stmt.Condition) {
			const context: Record<string, unknown> = {};
			if (params.externalId) {
				context["sts:ExternalId"] = params.externalId;
			}
			context["auth:principalType"] = params.principalType;

			if (
				!evaluateConditionBlock(
					stmt.Condition as Record<
						string,
						Record<string, string | string[] | number | boolean>
					>,
					context,
				)
			) {
				continue;
			}
		}

		return { allowed: true, matchedStatement: stmt };
	}

	return {
		allowed: false,
		reason: "No matching trust policy statement found",
	};
}

function matchesTrustPrincipal(
	stmt: PolicyStatement,
	params: TrustEvaluationParams,
): boolean {
	if (stmt.Principal === "*") return true;

	if (!stmt.Principal || typeof stmt.Principal !== "object") return false;

	for (const [type, values] of Object.entries(stmt.Principal)) {
		const valueList = Array.isArray(values) ? values : [values];

		if (type === "*") return true;

		const typeMatches =
			type === "IAM" ||
			type === "Federated" ||
			type === "Service" ||
			type === "AWS" ||
			type.toLowerCase() === params.principalType.toLowerCase();

		if (!typeMatches) continue;

		for (const v of valueList) {
			if (v === "*") return true;
			if (v === params.principalArn) return true;
			if (v.includes("*") || v.includes("?")) {
				if (globMatch(v, params.principalArn)) return true;
			}
		}
	}

	return false;
}
