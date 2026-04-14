import type {
	AuthorizationDecision,
	AuthorizationRequest,
	PolicyDocument,
	PolicyStatement,
	PrincipalMap,
} from "../types";
import { matchActionList, matchARN, matchResourceList } from "./arn";
import { evaluateConditionBlock } from "./conditions";
import { substituteInStringOrArray } from "./variables";

interface PolicySet {
	identityPolicies: PolicyDocument[];
	resourcePolicies: PolicyDocument[];
	permissionBoundaries: PolicyDocument[];
	sessionPolicies: PolicyDocument[];
}

interface EngineContext {
	isRootUser: boolean;
	variableContext: Record<string, unknown>;
}

export function evaluate(
	request: AuthorizationRequest,
	policies: PolicySet,
	engineCtx: EngineContext,
): AuthorizationDecision {
	const path: string[] = [];

	if (engineCtx.isRootUser) {
		path.push("Root user bypass: ALLOW");
		return {
			decision: "ALLOWED",
			matchedStatements: [],
			evaluationPath: path,
		};
	}

	const allPolicies = [
		...policies.identityPolicies,
		...policies.resourcePolicies,
		...policies.permissionBoundaries,
		...policies.sessionPolicies,
	];

	path.push(
		`Evaluating ${allPolicies.length} policy documents (${policies.identityPolicies.length} identity, ${policies.resourcePolicies.length} resource, ${policies.permissionBoundaries.length} boundary, ${policies.sessionPolicies.length} session)`,
	);

	const explicitDenyStatements = findExplicitDeny(
		allPolicies,
		request,
		engineCtx.variableContext,
	);
	if (explicitDenyStatements.length > 0) {
		path.push(
			`Explicit DENY found in ${explicitDenyStatements.length} statement(s)`,
		);
		return {
			decision: "DENIED",
			matchedStatements: explicitDenyStatements,
			evaluationPath: path,
		};
	}
	path.push("No explicit deny found");

	if (policies.permissionBoundaries.length > 0) {
		const boundaryAllow = findAllow(
			policies.permissionBoundaries,
			request,
			engineCtx.variableContext,
		);
		if (boundaryAllow.length === 0) {
			path.push("Permission boundary does not allow this action");
			return {
				decision: "DENIED",
				matchedStatements: [],
				evaluationPath: path,
			};
		}
		path.push("Permission boundary allows this action");
	}

	if (policies.sessionPolicies.length > 0) {
		const sessionAllow = findAllow(
			policies.sessionPolicies,
			request,
			engineCtx.variableContext,
		);
		if (sessionAllow.length === 0) {
			path.push("Session policy does not allow this action");
			return {
				decision: "DENIED",
				matchedStatements: [],
				evaluationPath: path,
			};
		}
		path.push("Session policy allows this action");
	}

	const resourceAllow = findAllow(
		policies.resourcePolicies,
		request,
		engineCtx.variableContext,
	);
	if (resourceAllow.length > 0) {
		path.push("Resource policy explicitly allows this action");
		return {
			decision: "ALLOWED",
			matchedStatements: resourceAllow,
			evaluationPath: path,
		};
	}

	const identityAllow = findAllow(
		policies.identityPolicies,
		request,
		engineCtx.variableContext,
	);
	if (identityAllow.length > 0) {
		path.push(
			`Identity policy allows this action (${identityAllow.length} matching statement(s))`,
		);
		return {
			decision: "ALLOWED",
			matchedStatements: identityAllow,
			evaluationPath: path,
		};
	}

	path.push("No allow statement found in any policy (implicit deny)");
	return {
		decision: "IMPLICIT_DENY",
		matchedStatements: [],
		evaluationPath: path,
	};
}

function findExplicitDeny(
	documents: PolicyDocument[],
	request: AuthorizationRequest,
	variableCtx: Record<string, unknown>,
): PolicyStatement[] {
	const matched: PolicyStatement[] = [];
	for (const doc of documents) {
		for (const stmt of doc.Statement) {
			if (stmt.Effect !== "Deny") continue;
			if (statementMatches(stmt, request, variableCtx)) {
				matched.push(stmt);
			}
		}
	}
	return matched;
}

function findAllow(
	documents: PolicyDocument[],
	request: AuthorizationRequest,
	variableCtx: Record<string, unknown>,
): PolicyStatement[] {
	const matched: PolicyStatement[] = [];
	for (const doc of documents) {
		for (const stmt of doc.Statement) {
			if (stmt.Effect !== "Allow") continue;
			if (statementMatches(stmt, request, variableCtx)) {
				matched.push(stmt);
			}
		}
	}
	return matched;
}

function statementMatches(
	stmt: PolicyStatement,
	request: AuthorizationRequest,
	variableCtx: Record<string, unknown>,
): boolean {
	if (!matchesAction(stmt, request.action, variableCtx)) return false;
	if (!matchesResource(stmt, request.resource, variableCtx)) return false;
	if (!matchesPrincipal(stmt, request.principal, request.principalType))
		return false;
	if (stmt.Condition) {
		const condCtx = { ...request.context, ...variableCtx };
		if (
			!evaluateConditionBlock(
				stmt.Condition as Record<
					string,
					Record<string, string | string[] | number | boolean>
				>,
				condCtx,
			)
		) {
			return false;
		}
	}
	return true;
}

function matchesAction(
	stmt: PolicyStatement,
	action: string,
	variableCtx: Record<string, unknown>,
): boolean {
	if (stmt.Action) {
		const resolved = substituteInStringOrArray(
			stmt.Action,
			variableCtx as Record<string, string>,
		);
		return matchActionList(resolved, action);
	}
	if (stmt.NotAction) {
		const resolved = substituteInStringOrArray(
			stmt.NotAction,
			variableCtx as Record<string, string>,
		);
		return !matchActionList(resolved, action);
	}
	return true;
}

function matchesResource(
	stmt: PolicyStatement,
	resource: string,
	variableCtx: Record<string, unknown>,
): boolean {
	if (stmt.Resource) {
		const resolved = substituteInStringOrArray(
			stmt.Resource,
			variableCtx as Record<string, string>,
		);
		return matchResourceList(resolved, resource);
	}
	if (stmt.NotResource) {
		const resolved = substituteInStringOrArray(
			stmt.NotResource,
			variableCtx as Record<string, string>,
		);
		return !matchResourceList(resolved, resource);
	}
	return true;
}

function matchesPrincipal(
	stmt: PolicyStatement,
	principal: string,
	principalType: string,
): boolean {
	if (stmt.Principal === undefined && stmt.NotPrincipal === undefined) {
		return true;
	}

	if (stmt.Principal === "*") return true;

	if (typeof stmt.Principal === "string" && stmt.Principal !== "*") {
		return stmt.Principal === principal;
	}

	if (stmt.Principal && typeof stmt.Principal === "object") {
		if (matchPrincipalMap(stmt.Principal, principal, principalType)) {
			return true;
		}
		return false;
	}

	if (stmt.NotPrincipal === "*") return false;

	if (typeof stmt.NotPrincipal === "string" && stmt.NotPrincipal !== "*") {
		return stmt.NotPrincipal !== principal;
	}

	if (stmt.NotPrincipal && typeof stmt.NotPrincipal === "object") {
		return !matchPrincipalMap(stmt.NotPrincipal, principal, principalType);
	}

	return false;
}

function matchPrincipalMap(
	map: PrincipalMap,
	principal: string,
	principalType: string,
): boolean {
	for (const [type, values] of Object.entries(map)) {
		const valueList = Array.isArray(values) ? values : [values];
		if (type === "*") return true;

		const typeMatches =
			type.toLowerCase() === principalType.toLowerCase() ||
			type === "IAM" ||
			type === "Federated" ||
			type === "Service";

		if (typeMatches) {
			for (const v of valueList) {
				if (v === "*" || v === principal || matchARN(v, principal)) {
					return true;
				}
			}
		}
	}
	return false;
}

export function createPolicySet(params: {
	identityPolicies?: PolicyDocument[];
	resourcePolicies?: PolicyDocument[];
	permissionBoundaries?: PolicyDocument[];
	sessionPolicies?: PolicyDocument[];
}): PolicySet {
	return {
		identityPolicies: params.identityPolicies ?? [],
		resourcePolicies: params.resourcePolicies ?? [],
		permissionBoundaries: params.permissionBoundaries ?? [],
		sessionPolicies: params.sessionPolicies ?? [],
	};
}

export function isAllowed(decision: AuthorizationDecision): boolean {
	return decision.decision === "ALLOWED";
}

export function isDenied(decision: AuthorizationDecision): boolean {
	return (
		decision.decision === "DENIED" || decision.decision === "IMPLICIT_DENY"
	);
}
