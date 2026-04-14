import { GLOBAL_CONTEXT_KEYS } from "../constants";

export function resolveMFAContextKeys(params: {
	twoFactorEnabled?: boolean;
	mfaVerifiedAt?: Date | null;
}): Record<string, unknown> {
	const context: Record<string, unknown> = {};

	context[GLOBAL_CONTEXT_KEYS.MFA_PRESENT] = String(
		params.twoFactorEnabled === true,
	);

	if (params.mfaVerifiedAt) {
		const ageSeconds = Math.floor(
			(Date.now() - params.mfaVerifiedAt.getTime()) / 1000,
		);
		context[GLOBAL_CONTEXT_KEYS.MFA_AGE] = ageSeconds;
	}

	return context;
}
