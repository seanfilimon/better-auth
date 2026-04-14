import { IAM_ERROR_CODES } from "../error-codes";

export interface MFAEnforcementConfig {
	protectedActions: string[];
	maxAge?: number;
}

export function checkMFARequired(
	action: string,
	config: MFAEnforcementConfig,
	mfaState: {
		twoFactorEnabled?: boolean;
		mfaVerifiedAt?: Date | null;
	},
): { required: boolean; error?: string } {
	const isProtected = config.protectedActions.some((pa) => {
		if (pa === action) return true;
		if (pa.endsWith("*")) {
			return action.startsWith(pa.slice(0, -1));
		}
		return false;
	});

	if (!isProtected) return { required: false };

	if (!mfaState.twoFactorEnabled) {
		return {
			required: true,
			error: IAM_ERROR_CODES.MFA_NOT_CONFIGURED.message,
		};
	}

	if (!mfaState.mfaVerifiedAt) {
		return {
			required: true,
			error: IAM_ERROR_CODES.MFA_REQUIRED.message,
		};
	}

	if (config.maxAge) {
		const ageSeconds = Math.floor(
			(Date.now() - mfaState.mfaVerifiedAt.getTime()) / 1000,
		);
		if (ageSeconds > config.maxAge) {
			return {
				required: true,
				error: IAM_ERROR_CODES.MFA_REQUIRED.message,
			};
		}
	}

	return { required: false };
}
