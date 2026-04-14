import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-auth";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";

const policyStatementSchema = z.object({
	Sid: z.string().optional(),
	Effect: z.enum(["Allow", "Deny"]),
	Action: z.union([z.string(), z.array(z.string())]).optional(),
	NotAction: z.union([z.string(), z.array(z.string())]).optional(),
	Resource: z.union([z.string(), z.array(z.string())]).optional(),
	NotResource: z.union([z.string(), z.array(z.string())]).optional(),
	Principal: z.any().optional(),
	NotPrincipal: z.any().optional(),
	Condition: z.any().optional(),
});

const policyDocumentSchema = z.object({
	Version: z.string(),
	Id: z.string().optional(),
	Statement: z.array(policyStatementSchema),
});

export function createPolicyRoutes(
	getAdapter: () => IamAdapter,
	hooks?: {
		beforeCreatePolicy?: (data: unknown) => Promise<{ data?: unknown } | void>;
		afterCreatePolicy?: (policy: unknown) => Promise<void>;
	},
) {
	const createPolicy = createAuthEndpoint(
		"/iam/policy/create",
		{
			method: "POST",
			body: z.object({
				name: z.string().min(1).max(128),
				path: z.string().optional(),
				description: z.string().optional(),
				type: z
					.enum(["managed", "inline", "boundary", "resource", "session"])
					.default("managed"),
				document: policyDocumentSchema,
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCreatePolicy" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			let { name, path, description, type, document } = ctx.body;
			const existing = await adapter.findPolicyByName(name);
			if (existing)
				throw new APIError("BAD_REQUEST", {
					message: IAM_ERROR_CODES.POLICY_ALREADY_EXISTS.message,
				});

			if (hooks?.beforeCreatePolicy) {
				const hookResult = await hooks.beforeCreatePolicy({
					name,
					path,
					description,
					type,
					document,
				});
				if (hookResult?.data) {
					const d = hookResult.data as any;
					name = d.name ?? name;
					path = d.path ?? path;
					description = d.description ?? description;
					type = d.type ?? type;
					document = d.document ?? document;
				}
			}

			const id = crypto.randomUUID();
			const versionId = "v1";
			const versionDbId = crypto.randomUUID();

			const policy = await adapter.createPolicy({
				id,
				name,
				path,
				description,
				type,
				defaultVersionId: versionId,
			});
			await adapter.createPolicyVersion({
				id: versionDbId,
				policyId: id,
				versionId,
				document,
				isDefault: true,
			});

			if (hooks?.afterCreatePolicy) {
				try {
					await hooks.afterCreatePolicy(policy);
				} catch {
					/* best effort */
				}
			}

			return { policy, versionId };
		},
	);

	const getPolicy = createAuthEndpoint(
		"/iam/policy/get",
		{
			method: "GET",
			query: z.object({ policyId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetPolicy" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			const policy = await adapter.findPolicyById(ctx.query.policyId);
			if (!policy)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.POLICY_NOT_FOUND.message,
				});
			return policy;
		},
	);

	const listPolicies = createAuthEndpoint(
		"/iam/policy/list",
		{
			method: "GET",
			query: z.object({
				type: z.string().optional(),
				path: z.string().optional(),
				limit: z.coerce.number().optional(),
				offset: z.coerce.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListPolicies" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			return adapter.listPolicies(ctx.query);
		},
	);

	const updatePolicy = createAuthEndpoint(
		"/iam/policy/update",
		{
			method: "POST",
			body: z.object({
				policyId: z.string(),
				description: z.string().optional(),
				path: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdatePolicy" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			const policy = await adapter.findPolicyById(ctx.body.policyId);
			if (!policy)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.POLICY_NOT_FOUND.message,
				});
			if ((policy as any).isServiceLinked)
				throw new APIError("FORBIDDEN", {
					message: IAM_ERROR_CODES.SERVICE_LINKED_POLICY_PROTECTED.message,
				});
			const { policyId, ...update } = ctx.body;
			return adapter.updatePolicy(policyId, update);
		},
	);

	const deletePolicy = createAuthEndpoint(
		"/iam/policy/delete",
		{
			method: "POST",
			body: z.object({ policyId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamDeletePolicy" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			const policy = await adapter.findPolicyById(ctx.body.policyId);
			if (!policy)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.POLICY_NOT_FOUND.message,
				});
			if ((policy as any).isServiceLinked)
				throw new APIError("FORBIDDEN", {
					message: IAM_ERROR_CODES.SERVICE_LINKED_POLICY_PROTECTED.message,
				});
			const count = await adapter.countAttachmentsByPolicy(ctx.body.policyId);
			if (count > 0)
				throw new APIError("BAD_REQUEST", {
					message: IAM_ERROR_CODES.POLICY_IN_USE.message,
				});
			await adapter.deletePolicyVersionsByPolicy(ctx.body.policyId);
			await adapter.deletePolicy(ctx.body.policyId);
			return { success: true };
		},
	);

	const createPolicyVersion = createAuthEndpoint(
		"/iam/policy/create-version",
		{
			method: "POST",
			body: z.object({
				policyId: z.string(),
				document: policyDocumentSchema,
				setAsDefault: z.boolean().default(false),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCreatePolicyVersion" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			const policy = await adapter.findPolicyById(ctx.body.policyId);
			if (!policy)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.POLICY_NOT_FOUND.message,
				});

			const count = await adapter.countPolicyVersions(ctx.body.policyId);
			if (count >= ((policy as any).maxVersions ?? 5)) {
				throw new APIError("BAD_REQUEST", {
					message: IAM_ERROR_CODES.POLICY_VERSION_LIMIT_EXCEEDED.message,
				});
			}

			const versionId = `v${count + 1}`;
			const id = crypto.randomUUID();
			const version = await adapter.createPolicyVersion({
				id,
				policyId: ctx.body.policyId,
				versionId,
				document: ctx.body.document,
				isDefault: ctx.body.setAsDefault,
			});

			if (ctx.body.setAsDefault) {
				const existing = await adapter.listPolicyVersions(ctx.body.policyId);
				for (const v of existing) {
					if ((v as any).id !== id && (v as any).isDefault) {
						await adapter.updatePolicyVersion((v as any).id, {
							isDefault: false,
						});
					}
				}
				await adapter.updatePolicy(ctx.body.policyId, {
					defaultVersionId: versionId,
				});
			}

			return { version, versionId };
		},
	);

	const setDefaultPolicyVersion = createAuthEndpoint(
		"/iam/policy/set-default-version",
		{
			method: "POST",
			body: z.object({ policyId: z.string(), versionId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamSetDefaultPolicyVersion" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			const version = await adapter.findPolicyVersion(
				ctx.body.policyId,
				ctx.body.versionId,
			);
			if (!version)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.POLICY_VERSION_NOT_FOUND.message,
				});

			const allVersions = await adapter.listPolicyVersions(ctx.body.policyId);
			for (const v of allVersions) {
				await adapter.updatePolicyVersion((v as any).id, {
					isDefault: (v as any).versionId === ctx.body.versionId,
				});
			}
			await adapter.updatePolicy(ctx.body.policyId, {
				defaultVersionId: ctx.body.versionId,
			});
			return { success: true };
		},
	);

	const listPolicyVersions = createAuthEndpoint(
		"/iam/policy/list-versions",
		{
			method: "GET",
			query: z.object({ policyId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListPolicyVersions" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			return adapter.listPolicyVersions(ctx.query.policyId);
		},
	);

	const attachPolicy = createAuthEndpoint(
		"/iam/policy/attach",
		{
			method: "POST",
			body: z.object({
				policyId: z.string(),
				targetType: z.enum(["user", "role", "group"]),
				targetId: z.string(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamAttachPolicy" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			const policy = await adapter.findPolicyById(ctx.body.policyId);
			if (!policy)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.POLICY_NOT_FOUND.message,
				});

			const existing = await adapter.findAttachment(
				ctx.body.policyId,
				ctx.body.targetType,
				ctx.body.targetId,
			);
			if (existing)
				throw new APIError("BAD_REQUEST", {
					message: IAM_ERROR_CODES.POLICY_ALREADY_ATTACHED.message,
				});

			const id = crypto.randomUUID();
			const attachment = await adapter.attachPolicy({ id, ...ctx.body });
			await adapter.updatePolicy(ctx.body.policyId, {
				attachmentCount: ((policy as any).attachmentCount ?? 0) + 1,
			});
			return attachment;
		},
	);

	const detachPolicy = createAuthEndpoint(
		"/iam/policy/detach",
		{
			method: "POST",
			body: z.object({
				policyId: z.string(),
				targetType: z.enum(["user", "role", "group"]),
				targetId: z.string(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamDetachPolicy" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			const existing = await adapter.findAttachment(
				ctx.body.policyId,
				ctx.body.targetType,
				ctx.body.targetId,
			);
			if (!existing)
				throw new APIError("BAD_REQUEST", {
					message: IAM_ERROR_CODES.POLICY_NOT_ATTACHED.message,
				});

			await adapter.detachPolicy(
				ctx.body.policyId,
				ctx.body.targetType,
				ctx.body.targetId,
			);
			const policy = await adapter.findPolicyById(ctx.body.policyId);
			if (policy) {
				await adapter.updatePolicy(ctx.body.policyId, {
					attachmentCount: Math.max(
						0,
						((policy as any).attachmentCount ?? 1) - 1,
					),
				});
			}
			return { success: true };
		},
	);

	const listAttachments = createAuthEndpoint(
		"/iam/policy/list-attachments",
		{
			method: "GET",
			query: z.object({
				policyId: z.string().optional(),
				targetType: z.string().optional(),
				targetId: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListAttachments" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			if (ctx.query.policyId)
				return adapter.listAttachmentsByPolicy(ctx.query.policyId);
			if (ctx.query.targetType && ctx.query.targetId)
				return adapter.listAttachmentsByTarget(
					ctx.query.targetType,
					ctx.query.targetId,
				);
			return [];
		},
	);

	return {
		iamCreatePolicy: createPolicy,
		iamGetPolicy: getPolicy,
		iamListPolicies: listPolicies,
		iamUpdatePolicy: updatePolicy,
		iamDeletePolicy: deletePolicy,
		iamCreatePolicyVersion: createPolicyVersion,
		iamSetDefaultPolicyVersion: setDefaultPolicyVersion,
		iamListPolicyVersions: listPolicyVersions,
		iamAttachPolicy: attachPolicy,
		iamDetachPolicy: detachPolicy,
		iamListAttachments: listAttachments,
	};
}
