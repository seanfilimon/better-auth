import type { IamAdapter } from "../adapter";

export async function cleanupAuditLogs(
	iamAdapter: IamAdapter,
	retentionDays: number,
) {
	const cutoffDate = new Date();
	cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
	await iamAdapter.deleteAuditLogsBefore(cutoffDate);
	return { cutoffDate, retentionDays };
}
