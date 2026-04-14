import { createAuthEndpoint } from "@better-auth/core/api";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import * as tags from "../abac/tags";
import type { IamAdapter } from "../adapter";

export function createTagRoutes(
	getAdapter: () => IamAdapter,
	quotas: { maxTagsPerResource: number },
) {
	const setTags = createAuthEndpoint(
		"/iam/tag/set",
		{
			method: "POST",
			body: z.object({
				resourceType: z.enum([
					"user",
					"role",
					"group",
					"policy",
					"serviceAccount",
				]),
				resourceId: z.string(),
				tags: z.record(z.string()),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamSetTags" } },
		},
		async (ctx) => {
			await tags.setTags(
				getAdapter(),
				ctx.body.resourceType,
				ctx.body.resourceId,
				ctx.body.tags,
				quotas.maxTagsPerResource,
			);
			return { success: true };
		},
	);

	const removeTags = createAuthEndpoint(
		"/iam/tag/remove",
		{
			method: "POST",
			body: z.object({
				resourceType: z.enum([
					"user",
					"role",
					"group",
					"policy",
					"serviceAccount",
				]),
				resourceId: z.string(),
				keys: z.array(z.string()),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamRemoveTags" } },
		},
		async (ctx) => {
			await tags.removeTags(
				getAdapter(),
				ctx.body.resourceType,
				ctx.body.resourceId,
				ctx.body.keys,
			);
			return { success: true };
		},
	);

	const listTags = createAuthEndpoint(
		"/iam/tag/list",
		{
			method: "GET",
			query: z.object({
				resourceType: z.enum([
					"user",
					"role",
					"group",
					"policy",
					"serviceAccount",
				]),
				resourceId: z.string(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListTags" } },
		},
		async (ctx) => {
			return tags.listTags(
				getAdapter(),
				ctx.query.resourceType,
				ctx.query.resourceId,
			);
		},
	);

	return {
		iamSetTags: setTags,
		iamRemoveTags: removeTags,
		iamListTags: listTags,
	};
}
