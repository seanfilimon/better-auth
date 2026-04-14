import type { AuthContext } from "@better-auth/core";
import { createAuthEndpoint } from "@better-auth/core/api";
import { sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import type { IamAdapter } from "../adapter";
import {
	generateAccessReport,
	generateCredentialReport,
	queryAuditLogs,
} from "../audit/query";
import { cleanupAuditLogs } from "../audit/retention";
import { DEFAULT_AUDIT_RETENTION_DAYS } from "../constants";
import type { IamOptions } from "../types";

export function createAuditRoutes(
	getAdapter: () => IamAdapter,
	getCtx: () => AuthContext,
	options: IamOptions,
) {
	const query = createAuthEndpoint(
		"/iam/audit/query",
		{
			method: "GET",
			query: z.object({
				eventType: z.string().optional(),
				principalId: z.string().optional(),
				action: z.string().optional(),
				resource: z.string().optional(),
				startTime: z.string().optional(),
				endTime: z.string().optional(),
				responseStatus: z.string().optional(),
				limit: z.coerce.number().optional(),
				offset: z.coerce.number().optional(),
			}),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamQueryAuditLogs" } },
		},
		async (ctx) => {
			const filters = {
				...ctx.query,
				startTime: ctx.query.startTime
					? new Date(ctx.query.startTime)
					: undefined,
				endTime: ctx.query.endTime ? new Date(ctx.query.endTime) : undefined,
			};
			return queryAuditLogs(getAdapter(), filters);
		},
	);

	const credentialReport = createAuthEndpoint(
		"/iam/audit/credential-report",
		{
			method: "GET",
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCredentialReport" } },
		},
		async () => {
			return generateCredentialReport(getCtx(), getAdapter());
		},
	);

	const accessReport = createAuthEndpoint(
		"/iam/audit/access-report",
		{
			method: "GET",
			query: z.object({ resourceArn: z.string() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamAccessReport" } },
		},
		async (ctx) => {
			return generateAccessReport(getAdapter(), ctx.query.resourceArn);
		},
	);

	const cleanup = createAuthEndpoint(
		"/iam/audit/cleanup",
		{
			method: "POST",
			body: z.object({ retentionDays: z.number().optional() }),
			use: [sessionMiddleware],
			metadata: { openapi: { operationId: "iamCleanupAuditLogs" } },
		},
		async (ctx) => {
			const days =
				ctx.body.retentionDays ??
				options.audit?.retentionDays ??
				DEFAULT_AUDIT_RETENTION_DAYS;
			return cleanupAuditLogs(getAdapter(), days);
		},
	);

	return {
		iamQueryAuditLogs: query,
		iamCredentialReport: credentialReport,
		iamAccessReport: accessReport,
		iamCleanupAuditLogs: cleanup,
	};
}
