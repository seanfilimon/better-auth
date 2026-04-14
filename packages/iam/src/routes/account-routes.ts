import { createAuthEndpoint } from "@better-auth/core/api";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import type { IamOptions } from "../types";

export function createAccountRoutes(
	getAdapter: () => IamAdapter,
	options: IamOptions,
) {
	const getSettings = createAuthEndpoint(
		"/iam/account/get-settings",
		{
			method: "GET",
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetAccountSettings" } },
		},
		async () => {
			const accountId = options.accountId ?? "000000000000";
			const settings = await getAdapter().getAccountSettings(accountId);
			if (!settings) {
				return {
					accountId,
					accountAlias: null,
					passwordPolicy: options.passwordPolicy ?? null,
					maxSessionDuration: options.sts?.maxDuration ?? 3600,
				};
			}
			return settings;
		},
	);

	const updateSettings = createAuthEndpoint(
		"/iam/account/update-settings",
		{
			method: "POST",
			body: z.object({
				accountAlias: z.string().optional(),
				passwordPolicy: z
					.object({
						minLength: z.number().optional(),
						requireUppercase: z.boolean().optional(),
						requireLowercase: z.boolean().optional(),
						requireNumbers: z.boolean().optional(),
						requireSymbols: z.boolean().optional(),
						maxAgeDays: z.number().nullable().optional(),
						preventReuseCount: z.number().optional(),
					})
					.optional(),
				maxSessionDuration: z.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdateAccountSettings" } },
		},
		async (ctx) => {
			const accountId = options.accountId ?? "000000000000";
			const id = crypto.randomUUID();
			return getAdapter().upsertAccountSettings({
				id,
				accountId,
				...ctx.body,
			});
		},
	);

	return {
		iamGetAccountSettings: getSettings,
		iamUpdateAccountSettings: updateSettings,
	};
}
