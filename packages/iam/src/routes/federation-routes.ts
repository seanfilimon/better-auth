import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-auth";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";

export function createFederationRoutes(getAdapter: () => IamAdapter) {
	const createProvider = createAuthEndpoint(
		"/iam/federation/create-provider",
		{
			method: "POST",
			body: z.object({
				name: z.string().min(1).max(128),
				type: z.enum(["oidc", "saml", "web-identity"]),
				providerUrl: z.string().url(),
				clientId: z.string().optional(),
				clientSecret: z.string().optional(),
				audiences: z.array(z.string()).optional(),
				thumbprints: z.array(z.string()).optional(),
				claimMapping: z
					.array(
						z.object({
							source: z.string(),
							target: z.string(),
							transform: z.string().optional(),
						}),
					)
					.optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCreateFederationProvider" } },
		},
		async (ctx) => {
			const adapter = getAdapter();
			const existing = await adapter.findFederationProviderByName(
				ctx.body.name,
			);
			if (existing)
				throw new APIError("BAD_REQUEST", {
					message: IAM_ERROR_CODES.FEDERATION_PROVIDER_ALREADY_EXISTS.message,
				});

			const id = crypto.randomUUID();
			return adapter.createFederationProvider({ id, ...ctx.body });
		},
	);

	const getProvider = createAuthEndpoint(
		"/iam/federation/get-provider",
		{
			method: "GET",
			query: z.object({ providerId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamGetFederationProvider" } },
		},
		async (ctx) => {
			const provider = await getAdapter().findFederationProviderById(
				ctx.query.providerId,
			);
			if (!provider)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.FEDERATION_PROVIDER_NOT_FOUND.message,
				});
			const { clientSecret: _secret, ...safeProvider } = provider as any;
			return safeProvider;
		},
	);

	const listProviders = createAuthEndpoint(
		"/iam/federation/list-providers",
		{
			method: "GET",
			query: z.object({
				type: z.string().optional(),
				limit: z.coerce.number().optional(),
				offset: z.coerce.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamListFederationProviders" } },
		},
		async (ctx) => {
			const providers = await getAdapter().listFederationProviders(ctx.query);
			return (providers as any[]).map(({ clientSecret: _s, ...safe }) => safe);
		},
	);

	const updateProvider = createAuthEndpoint(
		"/iam/federation/update-provider",
		{
			method: "POST",
			body: z.object({
				providerId: z.string(),
				providerUrl: z.string().url().optional(),
				clientId: z.string().optional(),
				clientSecret: z.string().optional(),
				audiences: z.array(z.string()).optional(),
				thumbprints: z.array(z.string()).optional(),
				claimMapping: z
					.array(
						z.object({
							source: z.string(),
							target: z.string(),
							transform: z.string().optional(),
						}),
					)
					.optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUpdateFederationProvider" } },
		},
		async (ctx) => {
			const { providerId, ...data } = ctx.body;
			return getAdapter().updateFederationProvider(providerId, data);
		},
	);

	const deleteProvider = createAuthEndpoint(
		"/iam/federation/delete-provider",
		{
			method: "POST",
			body: z.object({ providerId: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamDeleteFederationProvider" } },
		},
		async (ctx) => {
			const provider = await getAdapter().findFederationProviderById(
				ctx.body.providerId,
			);
			if (!provider)
				throw new APIError("NOT_FOUND", {
					message: IAM_ERROR_CODES.FEDERATION_PROVIDER_NOT_FOUND.message,
				});
			await getAdapter().deleteFederationProvider(ctx.body.providerId);
			return { success: true };
		},
	);

	return {
		iamCreateFederationProvider: createProvider,
		iamGetFederationProvider: getProvider,
		iamListFederationProviders: listProviders,
		iamUpdateFederationProvider: updateProvider,
		iamDeleteFederationProvider: deleteProvider,
	};
}
