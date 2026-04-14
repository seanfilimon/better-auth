import type { AuthContext } from "@better-auth/core";
import type { IamAdapter } from "../adapter";
import { MAX_STS_DURATION } from "../constants";
import { IAM_ERROR_CODES } from "../error-codes";
import { evaluateTrustPolicy } from "../federation/trust";
import type { PolicyDocument, TemporaryCredentials } from "../types";
import { safeJsonParse } from "../utils/json";
import { issueTemporaryCredentials } from "./index";

export async function assumeRole(
	ctx: AuthContext,
	iamAdapter: IamAdapter,
	params: {
		roleId: string;
		callerUserId: string;
		callerPrincipalType: string;
		callerArn: string;
		sessionName: string;
		durationSeconds?: number;
		sessionPolicy?: PolicyDocument;
		sessionTags?: Record<string, string>;
		transitiveTagKeys?: string[];
		sourceIdentity?: string;
		externalId?: string;
	},
): Promise<TemporaryCredentials> {
	const role = await iamAdapter.findRoleById(params.roleId);
	if (!role) {
		throw new Error(IAM_ERROR_CODES.ROLE_NOT_FOUND.message);
	}

	const roleData = role as any;
	const trustPolicy = safeJsonParse<PolicyDocument | null>(
		roleData.trustPolicy,
		null,
	);

	if (!trustPolicy) {
		throw new Error(IAM_ERROR_CODES.ASSUME_ROLE_DENIED.message);
	}

	const trustResult = evaluateTrustPolicy(trustPolicy, {
		principalArn: params.callerArn,
		principalType: params.callerPrincipalType,
		externalId: params.externalId,
	});

	if (!trustResult.allowed) {
		throw new Error(IAM_ERROR_CODES.ASSUME_ROLE_DENIED.message);
	}

	const maxDuration = Math.min(
		roleData.maxSessionDuration ?? MAX_STS_DURATION,
		MAX_STS_DURATION,
	);
	const duration =
		params.durationSeconds ?? roleData.maxSessionDuration ?? 3600;
	if (duration < 900 || duration > maxDuration) {
		throw new Error(IAM_ERROR_CODES.STS_DURATION_EXCEEDED.message);
	}

	const id = crypto.randomUUID();
	const creds = await issueTemporaryCredentials(iamAdapter, {
		id,
		userId: params.callerUserId,
		roleId: params.roleId,
		durationSeconds: duration,
		sessionPolicy: params.sessionPolicy,
		sessionTags: params.sessionTags,
		transitiveTagKeys: params.transitiveTagKeys,
		sourceIdentity: params.sourceIdentity,
	});

	try {
		await ctx.internalAdapter.updateSession(params.callerUserId, {
			iamRoleId: params.roleId,
			iamSessionTags: params.sessionTags
				? JSON.stringify(params.sessionTags)
				: undefined,
			iamSourceIdentity: params.sourceIdentity,
		} as any);
	} catch {
		// Session update is best-effort; STS tokens work independently
	}

	return creds;
}

export async function assumeRoleChained(
	ctx: AuthContext,
	iamAdapter: IamAdapter,
	params: {
		roleId: string;
		callerUserId: string;
		callerPrincipalType: string;
		callerArn: string;
		currentSourceIdentity: string;
		currentTransitiveTagKeys?: string[];
		currentSessionTags?: Record<string, string>;
		sessionName: string;
		durationSeconds?: number;
		sessionPolicy?: PolicyDocument;
		newSessionTags?: Record<string, string>;
	},
): Promise<TemporaryCredentials> {
	const transitiveTagKeys = params.currentTransitiveTagKeys ?? [];
	const carriedTags: Record<string, string> = {};

	if (params.currentSessionTags) {
		for (const key of transitiveTagKeys) {
			if (params.currentSessionTags[key]) {
				carriedTags[key] = params.currentSessionTags[key];
			}
		}
	}

	const mergedTags = { ...carriedTags, ...params.newSessionTags };

	return assumeRole(ctx, iamAdapter, {
		roleId: params.roleId,
		callerUserId: params.callerUserId,
		callerPrincipalType: params.callerPrincipalType,
		callerArn: params.callerArn,
		sessionName: params.sessionName,
		durationSeconds: params.durationSeconds,
		sessionPolicy: params.sessionPolicy,
		sessionTags: mergedTags,
		transitiveTagKeys: transitiveTagKeys,
		sourceIdentity: params.currentSourceIdentity,
	});
}
