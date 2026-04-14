import { createAuthEndpoint } from "@better-auth/core/api";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import { analyzeAccess } from "../analysis/access-analyzer";
import { simulatePolicy } from "../analysis/simulator";
import { detectUnusedAccess } from "../analysis/unused-access";
import { validatePolicyBestPractices } from "../analysis/validator";

export function createAnalysisRoutes(getAdapter: () => IamAdapter) {
	const validate = createAuthEndpoint(
		"/iam/policy/validate",
		{
			method: "POST",
			body: z.object({ document: z.any() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamValidatePolicy" } },
		},
		async (ctx) => {
			const findings = validatePolicyBestPractices(ctx.body.document);
			return { findings, valid: !findings.some((f) => f.severity === "ERROR") };
		},
	);

	const simulate = createAuthEndpoint(
		"/iam/policy/simulate",
		{
			method: "POST",
			body: z.object({
				principalId: z.string(),
				principalType: z.string().default("User"),
				action: z.string(),
				resource: z.string(),
				contextEntries: z.record(z.any()).optional(),
				resourcePolicy: z.any().optional(),
				permissionBoundary: z.any().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamSimulatePolicy" } },
		},
		async (ctx) => {
			return simulatePolicy(getAdapter(), ctx.body);
		},
	);

	const access = createAuthEndpoint(
		"/iam/analysis/access",
		{
			method: "GET",
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamAnalyzeAccess" } },
		},
		async () => {
			return analyzeAccess(getAdapter());
		},
	);

	const unusedAccess = createAuthEndpoint(
		"/iam/analysis/unused-access",
		{
			method: "GET",
			query: z.object({
				daysThreshold: z.coerce.number().optional(),
				limit: z.coerce.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamUnusedAccess" } },
		},
		async (ctx) => {
			return detectUnusedAccess(getAdapter(), ctx.query);
		},
	);

	return {
		iamValidatePolicy: validate,
		iamSimulatePolicy: simulate,
		iamAnalyzeAccess: access,
		iamUnusedAccess: unusedAccess,
	};
}
