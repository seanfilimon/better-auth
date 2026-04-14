import type { IamAdapter } from "../adapter";
import { constantTimeEqual, hmacHash } from "../utils/crypto";
import { safeJsonParse } from "../utils/json";

export async function validateStsToken(
	iamAdapter: IamAdapter,
	accessKeyId: string,
	sessionToken: string,
): Promise<{
	valid: boolean;
	userId?: string;
	roleId?: string;
	sessionTags?: Record<string, string>;
	sourceIdentity?: string;
	sessionPolicy?: unknown;
}> {
	const token = await iamAdapter.findStsTokenByAccessKeyId(accessKeyId);
	if (!token) {
		return { valid: false };
	}

	const tokenData = token as any;

	if (new Date(tokenData.expiresAt) < new Date()) {
		await iamAdapter.deleteStsToken(tokenData.id);
		return { valid: false };
	}

	const sessionTokenHash = await hmacHash("iam-sts-credential", sessionToken);
	if (!constantTimeEqual(sessionTokenHash, tokenData.sessionToken)) {
		return { valid: false };
	}

	const sessionTags = safeJsonParse<Record<string, string> | undefined>(
		tokenData.sessionTags,
		undefined,
	);

	const sessionPolicy = safeJsonParse<unknown>(
		tokenData.sessionPolicyDocument,
		undefined,
	);

	return {
		valid: true,
		userId: tokenData.userId,
		roleId: tokenData.roleId,
		sessionTags,
		sourceIdentity: tokenData.sourceIdentity,
		sessionPolicy,
	};
}
