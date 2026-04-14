import type { IamAdapter } from "../adapter";
import {
	ACCESS_KEY_ID_LENGTH,
	ACCESS_KEY_PREFIX_TEMPORARY,
	DEFAULT_STS_DURATION,
	SECRET_KEY_LENGTH,
	SESSION_TOKEN_LENGTH,
} from "../constants";
import type { PolicyDocument, TemporaryCredentials } from "../types";
import { generateRandomString, hmacHash } from "../utils/crypto";

export async function issueTemporaryCredentials(
	iamAdapter: IamAdapter,
	params: {
		id: string;
		userId: string;
		roleId?: string;
		durationSeconds?: number;
		sessionPolicy?: PolicyDocument;
		sessionTags?: Record<string, string>;
		transitiveTagKeys?: string[];
		sourceIdentity?: string;
	},
): Promise<TemporaryCredentials> {
	const alphanumeric =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	const alphanumPlus = alphanumeric + "+/";

	const accessKeyId =
		ACCESS_KEY_PREFIX_TEMPORARY +
		generateRandomString(
			ACCESS_KEY_ID_LENGTH - ACCESS_KEY_PREFIX_TEMPORARY.length,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		);
	const secretAccessKey = generateRandomString(SECRET_KEY_LENGTH, alphanumPlus);
	const sessionToken = generateRandomString(SESSION_TOKEN_LENGTH, alphanumeric);

	const duration = params.durationSeconds ?? DEFAULT_STS_DURATION;
	const expiresAt = new Date(Date.now() + duration * 1000);

	const secretKeyHash = await hmacHash("iam-sts-credential", secretAccessKey);
	const sessionTokenHash = await hmacHash("iam-sts-credential", sessionToken);

	await iamAdapter.createStsToken({
		id: params.id,
		accessKeyId,
		secretKeyHash,
		sessionToken: sessionTokenHash,
		userId: params.userId,
		roleId: params.roleId,
		sessionPolicyDocument: params.sessionPolicy,
		sessionTags: params.sessionTags,
		transitiveTagKeys: params.transitiveTagKeys,
		sourceIdentity: params.sourceIdentity,
		expiresAt,
	});

	return {
		accessKeyId,
		secretAccessKey,
		sessionToken,
		expiration: expiresAt,
	};
}
