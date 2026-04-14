import { POLICY_VARIABLES, TAG_CONTEXT_KEY_PREFIXES } from "../constants";

interface VariableContext {
	principalId?: string;
	principalName?: string;
	principalType?: string;
	sourceIdentity?: string;
	currentTime?: string;
	epochTime?: string;
	secureTransport?: string;
	sourceIp?: string;
	userAgent?: string;
	orgId?: string;
	teamId?: string;
	principalTags?: Record<string, string>;
	[key: string]: unknown;
}

export function substituteVariables(
	value: string,
	context: VariableContext,
): string {
	return value.replace(/\$\{([^}]+)\}/g, (_match, varName: string) => {
		const lower = varName.toLowerCase();

		if (lower.startsWith("iam:principaltag/")) {
			const tagKey = varName.substring("iam:principaltag/".length);
			return context.principalTags?.[tagKey] ?? "";
		}

		const mappedKey = POLICY_VARIABLES[lower];
		if (mappedKey && mappedKey in context) {
			return String(context[mappedKey] ?? "");
		}

		return "";
	});
}

export function substituteInStringOrArray(
	value: string | string[],
	context: VariableContext,
): string | string[] {
	if (Array.isArray(value)) {
		return value.map((v) => substituteVariables(v, context));
	}
	return substituteVariables(value, context);
}

export function buildVariableContext(params: {
	principalId: string;
	principalName: string;
	principalType: string;
	sourceIdentity?: string;
	sourceIp?: string;
	userAgent?: string;
	isSecure?: boolean;
	orgId?: string;
	teamId?: string;
	principalTags?: Record<string, string>;
}): VariableContext {
	const now = new Date();
	return {
		principalId: params.principalId,
		principalName: params.principalName,
		principalType: params.principalType,
		sourceIdentity: params.sourceIdentity ?? "",
		currentTime: now.toISOString(),
		epochTime: String(Math.floor(now.getTime() / 1000)),
		secureTransport: String(params.isSecure ?? false),
		sourceIp: params.sourceIp ?? "",
		userAgent: params.userAgent ?? "",
		orgId: params.orgId ?? "",
		teamId: params.teamId ?? "",
		principalTags: params.principalTags ?? {},
	};
}

export function resolveTagContextKeys(params: {
	principalTags?: Record<string, string>;
	resourceTags?: Record<string, string>;
	requestTags?: Record<string, string>;
}): Record<string, string> {
	const keys: Record<string, string> = {};

	if (params.principalTags) {
		for (const [k, v] of Object.entries(params.principalTags)) {
			keys[`${TAG_CONTEXT_KEY_PREFIXES.PRINCIPAL_TAG}${k}`] = v;
		}
	}
	if (params.resourceTags) {
		for (const [k, v] of Object.entries(params.resourceTags)) {
			keys[`${TAG_CONTEXT_KEY_PREFIXES.RESOURCE_TAG}${k}`] = v;
		}
	}
	if (params.requestTags) {
		for (const [k, v] of Object.entries(params.requestTags)) {
			keys[`${TAG_CONTEXT_KEY_PREFIXES.REQUEST_TAG}${k}`] = v;
		}
	}

	return keys;
}
