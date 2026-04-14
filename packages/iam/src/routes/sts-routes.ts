import type { AuthContext } from "@better-auth/core";
import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-auth";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";
import { assumeRole } from "../sts/assume-role";
import { issueTemporaryCredentials } from "../sts/index";
import { getCallerIdentity } from "../sts/session";
import type { IamOptions } from "../types";

export function createStsRoutes(
	getAdapter: () => IamAdapter,
	getCtx: () => AuthContext,
	options: IamOptions,
) {
	const stsAssumeRole = createAuthEndpoint(
		"/iam/sts/assume-role",
		{
			method: "POST",
			body: z.object({
				roleId: z.string(),
				sessionName: z.string().min(2).max(64),
				durationSeconds: z.number().optional(),
				sessionPolicy: z.any().optional(),
				sessionTags: z.record(z.string()).optional(),
				transitiveTagKeys: z.array(z.string()).optional(),
				sourceIdentity: z.string().optional(),
				externalId: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamAssumeRole" } },
		},
		async (ctx) => {
			const session = ctx.context.session;
			const partition = options.partition ?? "auth";
			const accountId = options.accountId ?? "000000000000";
			const callerArn = `arn:${partition}:iam::${accountId}:user/${session.user.id}`;

			if (options.hooks?.beforeAssumeRole) {
				const hookResult = await options.hooks.beforeAssumeRole(ctx.body);
				if (hookResult?.data) {
					Object.assign(ctx.body, hookResult.data);
				}
			}

			const creds = await assumeRole(getCtx(), getAdapter(), {
				...ctx.body,
				callerUserId: session.user.id,
				callerPrincipalType: "User",
				callerArn,
			});

			if (options.hooks?.afterAssumeRole) {
				try {
					await options.hooks.afterAssumeRole({
						...creds,
						roleId: ctx.body.roleId,
						userId: session.user.id,
					});
				} catch {
					/* best effort */
				}
			}

			return creds;
		},
	);

	const stsGetSessionToken = createAuthEndpoint(
		"/iam/sts/get-session-token",
		{
			method: "POST",
			body: z.object({ durationSeconds: z.number().optional() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetSessionToken" } },
		},
		async (ctx) => {
			const session = ctx.context.session;
			const id = crypto.randomUUID();
			return issueTemporaryCredentials(getAdapter(), {
				id,
				userId: session.user.id,
				durationSeconds: ctx.body.durationSeconds,
			});
		},
	);

	const stsGetCallerIdentity = createAuthEndpoint(
		"/iam/sts/get-caller-identity",
		{
			method: "GET",
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetCallerIdentity" } },
		},
		async (ctx) => {
			const session = ctx.context.session;
			return getCallerIdentity(getAdapter(), {
				userId: session.user.id,
				accountId: options.accountId ?? "000000000000",
				partition: options.partition ?? "auth",
				principalType: (session.session as any).iamRoleId
					? "AssumedRole"
					: "User",
				assumedRoleId: (session.session as any).iamRoleId,
			});
		},
	);

	const stsAssumeRoleWithWebIdentity = createAuthEndpoint(
		"/iam/sts/assume-role-with-web-identity",
		{
			method: "POST",
			body: z.object({
				roleId: z.string(),
				token: z.string(),
				providerId: z.string(),
				durationSeconds: z.number().optional(),
			}),
			metadata: { openapi: { operationId: "iamAssumeRoleWithWebIdentity" } },
		},
		async (ctx) => {
			const { assumeRoleWithWebIdentity } = await import(
				"../federation/web-identity"
			);
			return assumeRoleWithWebIdentity(getCtx(), getAdapter(), ctx.body);
		},
	);

	const stsAssumeRoleWithSaml = createAuthEndpoint(
		"/iam/sts/assume-role-with-saml",
		{
			method: "POST",
			body: z.object({
				roleId: z.string(),
				samlResponse: z.string(),
				providerId: z.string(),
				durationSeconds: z.number().optional(),
			}),
			metadata: { openapi: { operationId: "iamAssumeRoleWithSAML" } },
		},
		async (ctx) => {
			const { parseSAMLResponse, validateSAMLAssertion } = await import(
				"../federation/saml"
			);
			const { evaluateTrustPolicy } = await import("../federation/trust");
			const adapter = getAdapter();

			const assertion = parseSAMLResponse(ctx.body.samlResponse);
			if (!assertion)
				throw new APIError("BAD_REQUEST", {
					message: IAM_ERROR_CODES.FEDERATION_SAML_INVALID.message,
				});

			const provider = await adapter.findFederationProviderById(
				ctx.body.providerId,
			);
			if (!provider)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.FEDERATION_PROVIDER_NOT_FOUND.message,
				});

			const providerData = provider as any;
			const audiences = providerData.audiences
				? typeof providerData.audiences === "string"
					? JSON.parse(providerData.audiences)
					: providerData.audiences
				: [];
			const validation = validateSAMLAssertion(assertion, {
				providerUrl: providerData.providerUrl,
				audiences,
			});
			if (!validation.valid)
				throw new APIError("BAD_REQUEST", {
					message:
						validation.error ?? IAM_ERROR_CODES.FEDERATION_SAML_INVALID.message,
				});

			const role = await adapter.findRoleById(ctx.body.roleId);
			if (!role)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.ROLE_NOT_FOUND.message,
				});

			const roleData = role as any;
			const trustPolicy =
				typeof roleData.trustPolicy === "string"
					? JSON.parse(roleData.trustPolicy)
					: roleData.trustPolicy;
			const trustResult = evaluateTrustPolicy(trustPolicy, {
				principalArn: providerData.providerUrl,
				principalType: "Federated",
			});
			if (!trustResult.allowed)
				throw new APIError("FORBIDDEN", {
					message: IAM_ERROR_CODES.ASSUME_ROLE_DENIED.message,
				});

			const { applyClaimMapping } = await import("../federation/claim-mapping");
			const claimMapping = providerData.claimMapping
				? typeof providerData.claimMapping === "string"
					? JSON.parse(providerData.claimMapping)
					: providerData.claimMapping
				: [];
			const sessionTags = applyClaimMapping(
				claimMapping,
				assertion.attributes as any,
			);

			const id = crypto.randomUUID();
			return issueTemporaryCredentials(adapter, {
				id,
				userId: assertion.subjectNameId,
				roleId: ctx.body.roleId,
				durationSeconds: ctx.body.durationSeconds,
				sessionTags,
				sourceIdentity: assertion.subjectNameId,
			});
		},
	);

	return {
		iamAssumeRole: stsAssumeRole,
		iamGetSessionToken: stsGetSessionToken,
		iamGetCallerIdentity: stsGetCallerIdentity,
		iamAssumeRoleWithWebIdentity: stsAssumeRoleWithWebIdentity,
		iamAssumeRoleWithSaml: stsAssumeRoleWithSaml,
	};
}
