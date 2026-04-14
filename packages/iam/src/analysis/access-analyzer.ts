import type { IamAdapter } from "../adapter";
import type {
	AccessAnalyzerFinding,
	PolicyDocument,
	PolicyStatement,
} from "../types";

export async function analyzeAccess(
	iamAdapter: IamAdapter,
): Promise<AccessAnalyzerFinding[]> {
	const findings: AccessAnalyzerFinding[] = [];

	const roles = await iamAdapter.listRoles({});
	for (const role of roles) {
		const roleData = role as any;
		const trustPolicy: PolicyDocument =
			typeof roleData.trustPolicy === "string"
				? JSON.parse(roleData.trustPolicy)
				: roleData.trustPolicy;

		if (!trustPolicy?.Statement) continue;

		for (const stmt of trustPolicy.Statement) {
			if (stmt.Effect !== "Allow") continue;
			checkPublicAccess(stmt, roleData, findings);
		}
	}

	const policies = await iamAdapter.listPolicies({ type: "resource" });
	for (const policy of policies) {
		const policyData = policy as any;
		if (!policyData.defaultVersionId) continue;

		const version = await iamAdapter.findPolicyVersion(
			policyData.id,
			policyData.defaultVersionId,
		);
		if (!version) continue;

		const doc: PolicyDocument =
			typeof (version as any).document === "string"
				? JSON.parse((version as any).document)
				: (version as any).document;

		for (const stmt of doc.Statement) {
			if (stmt.Effect !== "Allow") continue;
			checkResourcePolicyAccess(stmt, policyData, findings);
		}
	}

	return findings;
}

function checkPublicAccess(
	stmt: PolicyStatement,
	roleData: any,
	findings: AccessAnalyzerFinding[],
) {
	if (stmt.Principal === "*") {
		if (!stmt.Condition || Object.keys(stmt.Condition).length === 0) {
			findings.push({
				severity: "WARNING",
				findingType: "public-access",
				resource: `role/${roleData.name}`,
				principal: "*",
				action: "sts:AssumeRole",
				recommendation:
					"Add conditions to restrict who can assume this role, or specify specific principals",
			});
		} else {
			findings.push({
				severity: "SUGGESTION",
				findingType: "public-access",
				resource: `role/${roleData.name}`,
				principal: "*",
				action: "sts:AssumeRole",
				condition: JSON.stringify(stmt.Condition),
				recommendation:
					"Trust policy allows any principal with conditions. Verify conditions are sufficiently restrictive.",
			});
		}
	}
}

function checkResourcePolicyAccess(
	stmt: PolicyStatement,
	policyData: any,
	findings: AccessAnalyzerFinding[],
) {
	if (stmt.Principal === "*") {
		const actions = stmt.Action
			? Array.isArray(stmt.Action)
				? stmt.Action
				: [stmt.Action]
			: ["*"];

		for (const action of actions) {
			findings.push({
				severity: "WARNING",
				findingType: "public-access",
				resource: policyData.name,
				principal: "*",
				action: String(action),
				recommendation:
					"Resource policy grants public access. Restrict principals or add conditions.",
			});
		}
	}

	if (stmt.Principal && typeof stmt.Principal === "object") {
		for (const [_type, values] of Object.entries(stmt.Principal)) {
			const valueList = Array.isArray(values) ? values : [values];
			for (const v of valueList) {
				if (v === "*") {
					findings.push({
						severity: "WARNING",
						findingType: "overly-permissive",
						resource: policyData.name,
						principal: v,
						action: String(stmt.Action ?? "*"),
						recommendation:
							"Wildcard principal detected in resource policy. Restrict to specific principals.",
					});
				}
			}
		}
	}
}
