import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-auth";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";
import * as groups from "../principals/groups";

export function createGroupRoutes(
	getAdapter: () => IamAdapter,
	quotas: { maxGroupsPerUser: number },
) {
	const createGroup = createAuthEndpoint(
		"/iam/group/create",
		{
			method: "POST",
			body: z.object({
				name: z.string().min(1).max(128),
				path: z.string().optional(),
				description: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCreateGroup" } },
		},
		async (ctx) => {
			const id = crypto.randomUUID();
			return groups.createGroup(getAdapter(), { id, ...ctx.body });
		},
	);

	const getGroup = createAuthEndpoint(
		"/iam/group/get",
		{
			method: "GET",
			query: z.object({ groupId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetGroup" } },
		},
		async (ctx) => {
			const group = await groups.getGroup(getAdapter(), ctx.query.groupId);
			if (!group)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.GROUP_NOT_FOUND.message,
				});
			return group;
		},
	);

	const listGroups = createAuthEndpoint(
		"/iam/group/list",
		{
			method: "GET",
			query: z.object({
				path: z.string().optional(),
				limit: z.coerce.number().optional(),
				offset: z.coerce.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListGroups" } },
		},
		async (ctx) => {
			return groups.listGroups(getAdapter(), ctx.query);
		},
	);

	const updateGroup = createAuthEndpoint(
		"/iam/group/update",
		{
			method: "POST",
			body: z.object({
				groupId: z.string(),
				name: z.string().optional(),
				path: z.string().optional(),
				description: z.string().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdateGroup" } },
		},
		async (ctx) => {
			const { groupId, ...data } = ctx.body;
			return groups.updateGroup(getAdapter(), groupId, data);
		},
	);

	const deleteGroup = createAuthEndpoint(
		"/iam/group/delete",
		{
			method: "POST",
			body: z.object({ groupId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamDeleteGroup" } },
		},
		async (ctx) => {
			await groups.deleteGroup(getAdapter(), ctx.body.groupId);
			return { success: true };
		},
	);

	const addUserToGroup = createAuthEndpoint(
		"/iam/group/add-user",
		{
			method: "POST",
			body: z.object({ userId: z.string(), groupId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamAddUserToGroup" } },
		},
		async (ctx) => {
			const id = crypto.randomUUID();
			return groups.addUserToGroup(
				getAdapter(),
				{ id, ...ctx.body },
				quotas.maxGroupsPerUser,
			);
		},
	);

	const removeUserFromGroup = createAuthEndpoint(
		"/iam/group/remove-user",
		{
			method: "POST",
			body: z.object({ userId: z.string(), groupId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamRemoveUserFromGroup" } },
		},
		async (ctx) => {
			await groups.removeUserFromGroup(
				getAdapter(),
				ctx.body.userId,
				ctx.body.groupId,
			);
			return { success: true };
		},
	);

	return {
		iamCreateGroup: createGroup,
		iamGetGroup: getGroup,
		iamListGroups: listGroups,
		iamUpdateGroup: updateGroup,
		iamDeleteGroup: deleteGroup,
		iamAddUserToGroup: addUserToGroup,
		iamRemoveUserFromGroup: removeUserFromGroup,
	};
}
