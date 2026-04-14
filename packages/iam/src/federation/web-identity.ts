import type { AuthContext } from "@better-auth/core";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";
import { issueTemporaryCredentials } from "../sts/index";
import type { TemporaryCredentials } from "../types";
import { safeJsonParse } from "../utils/json";
import { applyClaimMapping } from "./claim-mapping";
import { validateOIDCToken } from "./oidc";
import { evaluateTrustPolicy } from "./trust";

export async function assumeRoleWithWebIdentity(
	ctx: AuthContext,
	iamAdapter: IamAdapter,
	params: {
		roleId: string;
		token: string;
		providerId: string;
		durationSeconds?: number;
		sessionPolicy?: unknown;
	},
): Promise<TemporaryCredentials> {
	const provider = await iamAdapter.findFederationProviderById(
		params.providerId,
	);
	if (!provider) {
		throw new Error(IAM_ERROR_CODES.FEDERATION_PROVIDER_NOT_FOUND.message);
	}

	const providerData = provider as any;
	const audiences = safeJsonParse<string[]>(providerData.audiences, []);

	const validation = await validateOIDCToken(params.token, {
		providerUrl: providerData.providerUrl,
		clientId: providerData.clientId,
		audiences,
		metadataDocument: safeJsonParse<any>(
			providerData.metadataDocument,
			undefined,
		),
	});

	if (!validation.valid) {
		throw new Error(
			validation.error ?? IAM_ERROR_CODES.FEDERATION_TOKEN_INVALID.message,
		);
	}

	const role = await iamAdapter.findRoleById(params.roleId);
	if (!role) {
		throw new Error(IAM_ERROR_CODES.ROLE_NOT_FOUND.message);
	}

	const roleData = role as any;
	const trustPolicy = safeJsonParse<any>(roleData.trustPolicy, null);
	if (!trustPolicy) {
		throw new Error(IAM_ERROR_CODES.ASSUME_ROLE_DENIED.message);
	}

	const trustResult = evaluateTrustPolicy(trustPolicy, {
		principalArn: providerData.providerUrl,
		principalType: "Federated",
	});

	if (!trustResult.allowed) {
		throw new Error(IAM_ERROR_CODES.ASSUME_ROLE_DENIED.message);
	}

	const claimMapping = safeJsonParse<any[]>(providerData.claimMapping, []);

	const sessionTags = applyClaimMapping(claimMapping, validation.claims ?? {});

	const subjectId = String(
		validation.claims?.sub ?? validation.claims?.email ?? "unknown",
	);

	const id = crypto.randomUUID();
	return issueTemporaryCredentials(iamAdapter, {
		id,
		userId: subjectId,
		roleId: params.roleId,
		durationSeconds: params.durationSeconds,
		sessionTags,
		sourceIdentity: subjectId,
	});
}
