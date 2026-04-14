import { GLOBAL_CONTEXT_KEYS } from "../constants";

interface ContextKeyResolutionParams {
	request?: Request;
	userId?: string;
	userTwoFactorEnabled?: boolean;
	mfaVerifiedAt?: Date | null;
	activeOrganizationId?: string;
	principalType?: string;
	isServiceAccount?: boolean;
	isAnonymous?: boolean;
}

export function resolveGlobalContextKeys(
	params: ContextKeyResolutionParams,
): Record<string, unknown> {
	const now = new Date();
	const context: Record<string, unknown> = {};

	context[GLOBAL_CONTEXT_KEYS.CURRENT_TIME] = now.toISOString();
	context[GLOBAL_CONTEXT_KEYS.EPOCH_TIME] = Math.floor(now.getTime() / 1000);

	if (params.request) {
		const url = new URL(params.request.url, "https://localhost");
		context[GLOBAL_CONTEXT_KEYS.SECURE_TRANSPORT] = String(
			url.protocol === "https:",
		);
		context[GLOBAL_CONTEXT_KEYS.SOURCE_IP] =
			params.request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
			params.request.headers.get("x-real-ip") ??
			"";
		context[GLOBAL_CONTEXT_KEYS.USER_AGENT] =
			params.request.headers.get("user-agent") ?? "";
	}

	context[GLOBAL_CONTEXT_KEYS.MFA_PRESENT] = String(
		params.userTwoFactorEnabled === true,
	);

	if (params.mfaVerifiedAt) {
		const ageSeconds = Math.floor(
			(now.getTime() - params.mfaVerifiedAt.getTime()) / 1000,
		);
		context[GLOBAL_CONTEXT_KEYS.MFA_AGE] = ageSeconds;
	}

	if (params.activeOrganizationId) {
		context[GLOBAL_CONTEXT_KEYS.PRINCIPAL_ORG_ID] = params.activeOrganizationId;
	}

	if (params.principalType) {
		context[GLOBAL_CONTEXT_KEYS.PRINCIPAL_TYPE] = params.principalType;
	}

	context[GLOBAL_CONTEXT_KEYS.PRINCIPAL_IS_SERVICE_ACCOUNT] = String(
		params.isServiceAccount === true,
	);
	context[GLOBAL_CONTEXT_KEYS.PRINCIPAL_IS_ANONYMOUS] = String(
		params.isAnonymous === true,
	);

	return context;
}
