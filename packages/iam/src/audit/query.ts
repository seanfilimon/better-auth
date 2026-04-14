import type { AuthContext } from "@better-auth/core";
import type { IamAdapter } from "../adapter";
import type { CredentialReportEntry, PolicyDocument } from "../types";

export async function queryAuditLogs(
	iamAdapter: IamAdapter,
	filters: {
		eventType?: string;
		principalId?: string;
		action?: string;
		resource?: string;
		startTime?: Date;
		endTime?: Date;
		responseStatus?: string;
		limit?: number;
		offset?: number;
	},
) {
	return iamAdapter.queryAuditLogs(filters);
}

export async function generateCredentialReport(
	ctx: AuthContext,
	iamAdapter: IamAdapter,
): Promise<CredentialReportEntry[]> {
	const users = await ctx.internalAdapter.listUsers(1000, 0);
	const report: CredentialReportEntry[] = [];

	for (const user of users) {
		const userData = user as any;
		const accessKeys = await iamAdapter.listAccessKeysByUser(user.id);
		const key1 = accessKeys[0] as any | undefined;
		const key2 = accessKeys[1] as any | undefined;

		report.push({
			userId: user.id,
			userName: user.name,
			userPath: userData.iamPath ?? "/",
			userCreatedAt: user.createdAt,
			passwordLastUsed: userData.passwordLastUsed ?? null,
			passwordLastChanged: userData.passwordLastChanged ?? null,
			mfaActive: userData.twoFactorEnabled === true,
			accessKey1Id: key1?.id ?? null,
			accessKey1Status: key1?.status ?? null,
			accessKey1LastUsed: key1?.lastUsedAt ?? null,
			accessKey1LastRotated: key1?.createdAt ?? null,
			accessKey2Id: key2?.id ?? null,
			accessKey2Status: key2?.status ?? null,
			accessKey2LastUsed: key2?.lastUsedAt ?? null,
			accessKey2LastRotated: key2?.createdAt ?? null,
		});
	}

	return report;
}

export async function generateAccessReport(
	iamAdapter: IamAdapter,
	resourceArn: string,
) {
	const { matchResourceList } = await import("../policy/arn");
	const allPolicies = await iamAdapter.listPolicies({});
	const results: Array<{
		principalId: string;
		principalType: string;
		policyId: string;
		policyName: string;
		access: string;
		matchedActions: string[];
	}> = [];

	for (const policy of allPolicies) {
		const policyData = policy as any;
		if (!policyData.defaultVersionId) continue;

		const version = await iamAdapter.findPolicyVersion(
			policyData.id,
			policyData.defaultVersionId,
		);
		if (!version) continue;

		let doc: PolicyDocument | undefined;
		try {
			doc =
				typeof (version as any).document === "string"
					? JSON.parse((version as any).document)
					: (version as any).document;
		} catch {
			continue;
		}

		if (!doc?.Statement || !Array.isArray(doc.Statement)) continue;

		const matchedActions: string[] = [];
		for (const stmt of doc.Statement) {
			if (stmt.Effect !== "Allow") continue;

			const resources = stmt.Resource
				? Array.isArray(stmt.Resource)
					? stmt.Resource
					: [stmt.Resource]
				: [];

			const grantsResource = resources.some(
				(r: string) => r === "*" || matchResourceList(r, resourceArn),
			);

			if (grantsResource) {
				const actions = stmt.Action
					? Array.isArray(stmt.Action)
						? stmt.Action
						: [stmt.Action]
					: ["*"];
				matchedActions.push(...actions);
			}
		}

		if (matchedActions.length === 0) continue;

		const attachments = await iamAdapter.listAttachmentsByPolicy(policyData.id);

		for (const attachment of attachments) {
			const att = attachment as any;
			results.push({
				principalId: att.targetId,
				principalType: att.targetType,
				policyId: policyData.id,
				policyName: policyData.name,
				access: "via-policy",
				matchedActions,
			});
		}
	}

	return results;
}
