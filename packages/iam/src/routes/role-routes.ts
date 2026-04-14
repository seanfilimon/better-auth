import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-auth";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";
import * as roles from "../principals/roles";

const policyDocumentSchema = z.object({
	Version: z.string(),
	Id: z.string().optional(),
	Statement: z.array(z.any()),
});

export function createRoleRoutes(getAdapter: () => IamAdapter) {
	const createRole = createAuthEndpoint(
		"/iam/role/create",
		{
			method: "POST",
			body: z.object({
				name: z.string().min(1).max(128),
				path: z.string().optional(),
				description: z.string().optional(),
				trustPolicy: policyDocumentSchema,
				maxSessionDuration: z.number().optional(),
				permissionBoundaryId: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCreateRole" } },
		},
		async (ctx) => {
			const id = crypto.randomUUID();
			return roles.createRole(getAdapter(), { id, ...ctx.body });
		},
	);

	const getRole = createAuthEndpoint(
		"/iam/role/get",
		{
			method: "GET",
			query: z.object({ roleId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetRole" } },
		},
		async (ctx) => {
			const role = await roles.getRole(getAdapter(), ctx.query.roleId);
			if (!role)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.ROLE_NOT_FOUND.message,
				});
			return role;
		},
	);

	const listRoles = createAuthEndpoint(
		"/iam/role/list",
		{
			method: "GET",
			query: z.object({
				path: z.string().optional(),
				limit: z.coerce.number().optional(),
				offset: z.coerce.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListRoles" } },
		},
		async (ctx) => {
			return roles.listRoles(getAdapter(), ctx.query);
		},
	);

	const updateRole = createAuthEndpoint(
		"/iam/role/update",
		{
			method: "POST",
			body: z.object({
				roleId: z.string(),
				name: z.string().optional(),
				description: z.string().optional(),
				maxSessionDuration: z.number().optional(),
				permissionBoundaryId: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdateRole" } },
		},
		async (ctx) => {
			const { roleId, ...data } = ctx.body;
			return roles.updateRole(getAdapter(), roleId, data);
		},
	);

	const deleteRole = createAuthEndpoint(
		"/iam/role/delete",
		{
			method: "POST",
			body: z.object({ roleId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamDeleteRole" } },
		},
		async (ctx) => {
			await roles.deleteRole(getAdapter(), ctx.body.roleId);
			return { success: true };
		},
	);

	const updateTrustPolicy = createAuthEndpoint(
		"/iam/role/update-trust-policy",
		{
			method: "POST",
			body: z.object({ roleId: z.string(), trustPolicy: policyDocumentSchema }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdateTrustPolicy" } },
		},
		async (ctx) => {
			return roles.updateTrustPolicy(
				getAdapter(),
				ctx.body.roleId,
				ctx.body.trustPolicy,
			);
		},
	);

	return {
		iamCreateRole: createRole,
		iamGetRole: getRole,
		iamListRoles: listRoles,
		iamUpdateRole: updateRole,
		iamDeleteRole: deleteRole,
		iamUpdateTrustPolicy: updateTrustPolicy,
	};
}
