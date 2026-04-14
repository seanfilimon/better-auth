import type { AuthContext } from "@better-auth/core";
import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-auth";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";
import * as serviceAccounts from "../principals/service-accounts";

export function createServiceAccountRoutes(
	getAdapter: () => IamAdapter,
	getCtx: () => AuthContext,
) {
	const createServiceAccount = createAuthEndpoint(
		"/iam/service-account/create",
		{
			method: "POST",
			body: z.object({
				name: z.string().min(1).max(128),
				description: z.string().optional(),
				path: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCreateServiceAccount" } },
		},
		async (ctx) => {
			const id = crypto.randomUUID();
			return serviceAccounts.createServiceAccount(getCtx(), getAdapter(), {
				id,
				...ctx.body,
			});
		},
	);

	const getServiceAccount = createAuthEndpoint(
		"/iam/service-account/get",
		{
			method: "GET",
			query: z.object({ serviceAccountId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetServiceAccount" } },
		},
		async (ctx) => {
			const sa = await serviceAccounts.getServiceAccount(
				getAdapter(),
				ctx.query.serviceAccountId,
			);
			if (!sa)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.SERVICE_ACCOUNT_NOT_FOUND.message,
				});
			return sa;
		},
	);

	const listServiceAccounts = createAuthEndpoint(
		"/iam/service-account/list",
		{
			method: "GET",
			query: z.object({
				limit: z.coerce.number().optional(),
				offset: z.coerce.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListServiceAccounts" } },
		},
		async (ctx) => {
			return serviceAccounts.listServiceAccounts(getAdapter(), ctx.query);
		},
	);

	const updateServiceAccount = createAuthEndpoint(
		"/iam/service-account/update",
		{
			method: "POST",
			body: z.object({
				serviceAccountId: z.string(),
				name: z.string().optional(),
				description: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdateServiceAccount" } },
		},
		async (ctx) => {
			const { serviceAccountId, ...data } = ctx.body;
			return serviceAccounts.updateServiceAccount(
				getAdapter(),
				serviceAccountId,
				data,
			);
		},
	);

	const deleteServiceAccount = createAuthEndpoint(
		"/iam/service-account/delete",
		{
			method: "POST",
			body: z.object({ serviceAccountId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamDeleteServiceAccount" } },
		},
		async (ctx) => {
			await serviceAccounts.deleteServiceAccount(
				getCtx(),
				getAdapter(),
				ctx.body.serviceAccountId,
			);
			return { success: true };
		},
	);

	return {
		iamCreateServiceAccount: createServiceAccount,
		iamGetServiceAccount: getServiceAccount,
		iamListServiceAccounts: listServiceAccounts,
		iamUpdateServiceAccount: updateServiceAccount,
		iamDeleteServiceAccount: deleteServiceAccount,
	};
}
