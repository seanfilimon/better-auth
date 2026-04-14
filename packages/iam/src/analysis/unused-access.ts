import type { IamAdapter } from "../adapter";
import type { UnusedAccessFinding } from "../types";

export async function detectUnusedAccess(
	iamAdapter: IamAdapter,
	params: {
		daysThreshold?: number;
		limit?: number;
	},
): Promise<UnusedAccessFinding[]> {
	const daysThreshold = params.daysThreshold ?? 90;
	const findings: UnusedAccessFinding[] = [];

	const accessKeys = await iamAdapter.listPolicies({});
	const allAttachments: Array<{
		targetType: string;
		targetId: string;
		policyId: string;
		policyName: string;
	}> = [];

	for (const policy of accessKeys) {
		const policyData = policy as any;
		const attachments = await iamAdapter.listAttachmentsByPolicy(policyData.id);
		for (const att of attachments) {
			const attData = att as any;
			allAttachments.push({
				targetType: attData.targetType,
				targetId: attData.targetId,
				policyId: policyData.id,
				policyName: policyData.name,
			});
		}
	}

	const cutoff = new Date();
	cutoff.setDate(cutoff.getDate() - daysThreshold);

	for (const att of allAttachments) {
		const logs = await iamAdapter.queryAuditLogs({
			principalId: att.targetId,
			limit: 1,
			startTime: cutoff,
		});

		if (logs.length === 0) {
			findings.push({
				principalId: att.targetId,
				principalType: att.targetType,
				permission: `Policy: ${att.policyName}`,
				grantedVia: att.policyId,
				lastUsed: null,
				daysSinceUsed: null,
			});
		}
	}

	return findings.slice(0, params.limit ?? 100);
}
