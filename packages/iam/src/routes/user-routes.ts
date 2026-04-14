import type { AuthContext } from "@better-auth/core";
import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-auth";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";
import * as users from "../principals/users";

export function createUserRoutes(
	getAdapter: () => IamAdapter,
	getCtx: () => AuthContext,
) {
	const createUser = createAuthEndpoint(
		"/iam/user/create",
		{
			method: "POST",
			body: z.object({
				name: z.string().min(1),
				email: z.string().email(),
				iamPath: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCreateUser" } },
		},
		async (ctx) => {
			return users.createIamUser(getCtx(), getAdapter(), ctx.body);
		},
	);

	const getUser = createAuthEndpoint(
		"/iam/user/get",
		{
			method: "GET",
			query: z.object({ userId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetUser" } },
		},
		async (ctx) => {
			const user = await users.getIamUser(getCtx(), ctx.query.userId);
			if (!user)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.USER_NOT_FOUND.message,
				});
			return user;
		},
	);

	const listUsers = createAuthEndpoint(
		"/iam/user/list",
		{
			method: "GET",
			query: z.object({
				limit: z.coerce.number().optional(),
				offset: z.coerce.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListUsers" } },
		},
		async (ctx) => {
			return users.listIamUsers(getCtx(), ctx.query);
		},
	);

	const updateUser = createAuthEndpoint(
		"/iam/user/update",
		{
			method: "POST",
			body: z.object({
				userId: z.string(),
				name: z.string().optional(),
				iamPath: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdateUser" } },
		},
		async (ctx) => {
			const { userId, ...data } = ctx.body;
			return users.updateIamUser(getCtx(), userId, data);
		},
	);

	const deleteUser = createAuthEndpoint(
		"/iam/user/delete",
		{
			method: "POST",
			body: z.object({ userId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamDeleteUser" } },
		},
		async (ctx) => {
			await users.deleteIamUser(getCtx(), getAdapter(), ctx.body.userId);
			return { success: true };
		},
	);

	const listUserPolicies = createAuthEndpoint(
		"/iam/user/list-policies",
		{
			method: "GET",
			query: z.object({ userId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListUserPolicies" } },
		},
		async (ctx) => {
			return users.listUserEffectivePolicies(getAdapter(), ctx.query.userId);
		},
	);

	return {
		iamCreateUser: createUser,
		iamGetUser: getUser,
		iamListUsers: listUsers,
		iamUpdateUser: updateUser,
		iamDeleteUser: deleteUser,
		iamListUserPolicies: listUserPolicies,
	};
}
