import type { BetterAuthPlugin } from "better-auth";
import { defu } from "defu";
import { resolveABACContext } from "./abac/evaluation";
import type { IamAdapter } from "./adapter";
import { getIamAdapter } from "./adapter";
import type { AuditLogger } from "./audit/logger";
import { createAuditLogger } from "./audit/logger";
import { DEFAULT_PARTITION, DEFAULT_QUOTAS, IAM_PLUGIN_ID } from "./constants";
import { IAM_ERROR_CODES } from "./error-codes";
import { resolveMFAContextKeys } from "./mfa/conditions";
import { checkMFARequired } from "./mfa/enforcement";
import { buildIamARN } from "./policy/arn";
import { createPolicySet, evaluate } from "./policy/engine";
import { buildVariableContext } from "./policy/variables";
import { recordAccessKeyUsage } from "./principals/access-keys";
import { listUserEffectivePolicyDocuments } from "./principals/users";
import { createAccessKeyRoutes } from "./routes/access-key-routes";
import { createAccountRoutes } from "./routes/account-routes";
import { createAnalysisRoutes } from "./routes/analysis-routes";
import { createAuditRoutes } from "./routes/audit-routes";
import { createFederationRoutes } from "./routes/federation-routes";
import { createGroupRoutes } from "./routes/group-routes";
import { createPolicyRoutes } from "./routes/policy-routes";
import { createRoleRoutes } from "./routes/role-routes";
import { createServiceAccountRoutes } from "./routes/service-account-routes";
import { createStsRoutes } from "./routes/sts-routes";
import { createTagRoutes } from "./routes/tag-routes";
import { createUserRoutes } from "./routes/user-routes";
import { schema as iamSchema } from "./schema";
import {
	parseAuthorizationHeader,
	verifyRequestSignature,
} from "./sts/signing";
import type { AuthorizationRequest, IamOptions, PolicyDocument } from "./types";
import { PACKAGE_VERSION } from "./version";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		iam: {
			creator: typeof iam;
		};
	}
}

export const iam = (options: IamOptions = {}) => {
	const quotas = defu(options.quotas ?? {}, DEFAULT_QUOTAS);
	const partition = options.partition ?? DEFAULT_PARTITION;
	const accountId = options.accountId ?? "000000000000";
	const auditEnabled = options.audit?.enabled !== false;

	let _adapter: IamAdapter | null = null;
	let _auditLogger: AuditLogger | null = null;
	let _ctx: any = null;

	function getAdapter(): IamAdapter {
		if (!_adapter) throw new Error("IAM adapter not initialized");
		return _adapter;
	}
	function getCtx() {
		if (!_ctx) throw new Error("IAM context not initialized");
		return _ctx;
	}

	const policyRoutes = createPolicyRoutes(getAdapter, options.hooks);
	const userRoutes = createUserRoutes(getAdapter, getCtx);
	const groupRoutes = createGroupRoutes(getAdapter, quotas);
	const roleRoutes = createRoleRoutes(getAdapter);
	const accessKeyRoutes = createAccessKeyRoutes(getAdapter, quotas);
	const serviceAccountRoutes = createServiceAccountRoutes(getAdapter, getCtx);
	const stsRoutes = createStsRoutes(getAdapter, getCtx, options);
	const federationRoutes = createFederationRoutes(getAdapter);
	const tagRoutes = createTagRoutes(getAdapter, quotas);
	const auditRoutes = createAuditRoutes(getAdapter, getCtx, options);
	const analysisRoutes = createAnalysisRoutes(getAdapter);
	const accountRoutes = createAccountRoutes(getAdapter, options);

	return {
		id: IAM_PLUGIN_ID,
		version: PACKAGE_VERSION,
		$ERROR_CODES: IAM_ERROR_CODES,

		endpoints: {
			...policyRoutes,
			...userRoutes,
			...groupRoutes,
			...roleRoutes,
			...accessKeyRoutes,
			...serviceAccountRoutes,
			...stsRoutes,
			...federationRoutes,
			...tagRoutes,
			...auditRoutes,
			...analysisRoutes,
			...accountRoutes,
		},

		schema: iamSchema,

		init(ctx: any) {
			_ctx = ctx;
			_adapter = getIamAdapter(ctx);
			_auditLogger = createAuditLogger(_adapter, {
				enabled: auditEnabled,
				redactedFields: options.audit?.redactedFields,
				onEvent: options.audit?.onEvent,
			});

			return {
				options: {
					databaseHooks: {
						user: {
							delete: {
								async before(user: any) {
									if (!_adapter) return;
									try {
										await _adapter.deleteUserMemberships(user.id);
										await _adapter.deleteAttachmentsByTarget("user", user.id);
										await _adapter.deleteAccessKeysByUser(user.id);
										await _adapter.deleteStsTokensByUser(user.id);
										await _adapter.deleteTagsByResource("user", user.id);
									} catch {
										// Best-effort cascade cleanup
									}
								},
							},
						},
					},
				},
			};
		},

		async onRequest(request: Request, ctx: any) {
			if (!options.enforceOnAllRoutes) return { response: undefined };
			if (!_adapter) return { response: undefined };

			const url = new URL(request.url, "https://localhost");
			const path = url.pathname;

			if (path.startsWith("/iam/sts/assume-role-with")) {
				return { response: undefined };
			}

			const authHeader = request.headers.get("authorization");
			if (authHeader?.startsWith("IAM-HMAC")) {
				const parsed = parseAuthorizationHeader(authHeader);
				if (!parsed) {
					return {
						response: new Response(
							JSON.stringify({
								error: IAM_ERROR_CODES.SIGNING_INVALID.message,
							}),
							{ status: 401 },
						),
					};
				}

				const accessKey = await _adapter.findAccessKeyById(parsed.accessKeyId);
				if (!accessKey || (accessKey as any).status !== "active") {
					return {
						response: new Response(
							JSON.stringify({
								error: IAM_ERROR_CODES.SIGNING_INVALID.message,
							}),
							{ status: 401 },
						),
					};
				}

				const timestamp = request.headers.get("x-iam-date") ?? "";
				if (!timestamp) {
					return {
						response: new Response(
							JSON.stringify({ error: "Missing x-iam-date header" }),
							{ status: 401 },
						),
					};
				}

				const requestAge = Math.abs(Date.now() - new Date(timestamp).getTime());
				if (requestAge > 5 * 60 * 1000) {
					return {
						response: new Response(
							JSON.stringify({
								error: "Request timestamp too old or too far in the future",
							}),
							{ status: 401 },
						),
					};
				}

				const headersRecord: Record<string, string> = {};
				for (const h of parsed.signedHeaders) {
					headersRecord[h.toLowerCase()] = request.headers.get(h) ?? "";
				}

				let body: string | undefined;
				if (request.method !== "GET" && request.method !== "HEAD") {
					try {
						body = await request.clone().text();
					} catch {
						body = "";
					}
				}

				const isValidSig = await verifyRequestSignature({
					method: request.method,
					path: url.pathname,
					headers: headersRecord,
					body,
					secretKey: (accessKey as any).secretKeyHash,
					signedHeaders: parsed.signedHeaders,
					providedSignature: parsed.signature,
					timestamp,
				});

				if (!isValidSig) {
					return {
						response: new Response(
							JSON.stringify({
								error: IAM_ERROR_CODES.SIGNING_INVALID.message,
							}),
							{ status: 401 },
						),
					};
				}

				await recordAccessKeyUsage(_adapter, parsed.accessKeyId, "iam");
			}

			const actionMapping = options.actionMapping ?? {};
			const action = actionMapping[path];
			if (!action) return { response: undefined };

			const session = (ctx as any)?.session;
			if (!session?.user?.id) return { response: undefined };

			const userId = session.user.id;
			const isRoot = options.rootUserId ? userId === options.rootUserId : false;

			if (options.mfa?.protectedActions) {
				const mfaCheck = checkMFARequired(
					action,
					{
						protectedActions: options.mfa.protectedActions,
						maxAge: options.mfa.maxAge,
					},
					{
						twoFactorEnabled: session.user?.twoFactorEnabled,
						mfaVerifiedAt: session.session?.mfaVerifiedAt
							? new Date(session.session.mfaVerifiedAt)
							: null,
					},
				);

				if (mfaCheck.required) {
					return {
						response: new Response(JSON.stringify({ error: mfaCheck.error }), {
							status: 403,
						}),
					};
				}
			}

			const policyDocs = await listUserEffectivePolicyDocuments(
				_adapter,
				userId,
			);
			const identityDocs: PolicyDocument[] = policyDocs.map(
				(p) => p.document as PolicyDocument,
			);

			const userArn = buildIamARN(partition, accountId, "user", userId);
			const variableCtx = buildVariableContext({
				principalId: userId,
				principalName: session.user?.name ?? userId,
				principalType: "User",
				sourceIp: request.headers.get("x-forwarded-for")?.split(",")[0]?.trim(),
				userAgent: request.headers.get("user-agent") ?? "",
				isSecure: url.protocol === "https:",
			});

			const abacCtx = await resolveABACContext(_adapter, {
				principalId: userId,
				principalType: "User",
			});
			const mfaCtx = resolveMFAContextKeys({
				twoFactorEnabled: session.user?.twoFactorEnabled,
				mfaVerifiedAt: session.session?.mfaVerifiedAt
					? new Date(session.session.mfaVerifiedAt)
					: null,
			});

			const authRequest: AuthorizationRequest = {
				principal: userArn,
				principalType: "User",
				action,
				resource: url.pathname,
				context: { ...variableCtx, ...abacCtx, ...mfaCtx },
			};

			if (options.hooks?.beforeAuthorize) {
				const hookResult = await options.hooks.beforeAuthorize(authRequest);
				if (hookResult?.decision === "ALLOW") return { response: undefined };
				if (hookResult?.decision === "DENY") {
					return {
						response: new Response(
							JSON.stringify({
								error: IAM_ERROR_CODES.AUTHORIZATION_DENIED.message,
							}),
							{ status: 403 },
						),
					};
				}
			}

			const policySet = createPolicySet({ identityPolicies: identityDocs });
			const decision = evaluate(authRequest, policySet, {
				isRootUser: isRoot,
				variableContext: { ...variableCtx, ...abacCtx, ...mfaCtx },
			});

			if (options.hooks?.afterAuthorize) {
				try {
					await options.hooks.afterAuthorize(authRequest, decision);
				} catch {
					/* best effort */
				}
			}

			if (decision.decision !== "ALLOWED") {
				if (_auditLogger && auditEnabled) {
					try {
						await _auditLogger.log({
							eventType: "Denied",
							eventSource: "iam",
							principalId: userId,
							principalType: "User",
							action,
							resource: url.pathname,
							sourceIp:
								request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
								"",
							userAgent: request.headers.get("user-agent") ?? "",
							requestParams: {},
							responseStatus: "denied",
							errorCode: decision.decision,
							sessionId: session.session?.id,
							mfaAuthenticated: session.user?.twoFactorEnabled === true,
						});
					} catch {
						/* audit should never break */
					}
				}

				return {
					response: new Response(
						JSON.stringify({
							error:
								decision.decision === "DENIED"
									? IAM_ERROR_CODES.AUTHORIZATION_EXPLICIT_DENY.message
									: IAM_ERROR_CODES.AUTHORIZATION_IMPLICIT_DENY.message,
							evaluationPath: decision.evaluationPath,
						}),
						{ status: 403 },
					),
				};
			}

			return { response: undefined };
		},

		hooks: {
			after: [
				{
					matcher: (ctx: any) => true,
					handler: async (ctx: any) => {
						if (!_auditLogger || !auditEnabled) return { response: undefined };

						const path = ctx.path ?? "";
						if (!path.startsWith("/iam/")) return { response: undefined };

						try {
							const session = ctx.context?.session;
							await _auditLogger.log({
								eventType: path.split("/").pop() ?? "unknown",
								eventSource: "iam",
								principalId: session?.user?.id ?? "anonymous",
								principalType: session?.user?.id ? "User" : "Anonymous",
								action: path,
								resource: "",
								sourceIp:
									ctx.headers
										?.get?.("x-forwarded-for")
										?.split(",")[0]
										?.trim() ?? "",
								userAgent: ctx.headers?.get?.("user-agent") ?? "",
								requestParams: {},
								responseStatus:
									ctx.responseCode && ctx.responseCode >= 400
										? "error"
										: "success",
								sessionId: session?.session?.id,
								mfaAuthenticated: false,
							});
						} catch {
							// Audit logging should never break the response
						}
						return { response: undefined };
					},
				},
			],
		},
	} satisfies BetterAuthPlugin;
};

export { createEventStreamer } from "./audit/streaming";
export { IAM_ERROR_CODES } from "./error-codes";
export { checkMFARequired } from "./mfa/enforcement";
export { buildARN, buildIamARN, matchARN, parseARN } from "./policy/arn";
export { evaluateConditionBlock } from "./policy/conditions";
export {
	createPolicySet,
	evaluate,
	isAllowed,
	isDenied,
} from "./policy/engine";
export { validatePolicyDocument } from "./policy/validation";
export {
	parseAuthorizationHeader,
	signRequest,
	verifyRequestSignature,
} from "./sts/signing";
export type {
	AccessAnalyzerFinding,
	AuditEvent,
	AuthorizationDecision,
	AuthorizationRequest,
	ClaimMappingRule,
	CredentialReportEntry,
	IamOptions,
	IamQuotas,
	ParsedARN,
	PasswordPolicy,
	PolicyDocument,
	PolicyStatement,
	PolicyValidationFinding,
	STSCallerIdentity,
	TemporaryCredentials,
	UnusedAccessFinding,
} from "./types";
