import { createAuthEndpoint } from "@better-auth/core/api";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import * as accessKeys from "../principals/access-keys";

export function createAccessKeyRoutes(
	getAdapter: () => IamAdapter,
	quotas: { maxAccessKeysPerUser: number },
) {
	const createAccessKey = createAuthEndpoint(
		"/iam/access-key/create",
		{
			method: "POST",
			body: z.object({ userId: z.string().optional() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCreateAccessKey" } },
		},
		async (ctx) => {
			const targetUserId = ctx.body.userId ?? ctx.context.session.user.id;
			const result = await accessKeys.createAccessKey(
				getAdapter(),
				targetUserId,
				quotas.maxAccessKeysPerUser,
			);
			return {
				accessKeyId: result.accessKeyId,
				secretAccessKey: result.secretAccessKey,
			};
		},
	);

	const deleteAccessKey = createAuthEndpoint(
		"/iam/access-key/delete",
		{
			method: "POST",
			body: z.object({ accessKeyId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamDeleteAccessKey" } },
		},
		async (ctx) => {
			await accessKeys.deleteAccessKey(
				getAdapter(),
				ctx.body.accessKeyId,
				ctx.context.session.user.id,
			);
			return { success: true };
		},
	);

	const updateAccessKeyStatus = createAuthEndpoint(
		"/iam/access-key/update-status",
		{
			method: "POST",
			body: z.object({
				accessKeyId: z.string(),
				status: z.enum(["active", "inactive"]),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdateAccessKeyStatus" } },
		},
		async (ctx) => {
			return accessKeys.updateAccessKeyStatus(
				getAdapter(),
				ctx.body.accessKeyId,
				ctx.body.status,
			);
		},
	);

	const listAccessKeys = createAuthEndpoint(
		"/iam/access-key/list",
		{
			method: "GET",
			query: z.object({ userId: z.string().optional() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListAccessKeys" } },
		},
		async (ctx) => {
			const targetUserId = ctx.query.userId ?? ctx.context.session.user.id;
			return accessKeys.listAccessKeys(getAdapter(), targetUserId);
		},
	);

	const getAccessKeyLastUsed = createAuthEndpoint(
		"/iam/access-key/get-last-used",
		{
			method: "GET",
			query: z.object({ accessKeyId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetAccessKeyLastUsed" } },
		},
		async (ctx) => {
			return accessKeys.getAccessKeyLastUsed(
				getAdapter(),
				ctx.query.accessKeyId,
			);
		},
	);

	return {
		iamCreateAccessKey: createAccessKey,
		iamDeleteAccessKey: deleteAccessKey,
		iamUpdateAccessKeyStatus: updateAccessKeyStatus,
		iamListAccessKeys: listAccessKeys,
		iamGetAccessKeyLastUsed: getAccessKeyLastUsed,
	};
}
