import type { IamAdapter } from "../adapter";

export async function cleanupExpiredTokens(iamAdapter: IamAdapter) {
	await iamAdapter.deleteExpiredStsTokens();
}

export async function getCallerIdentity(
	iamAdapter: IamAdapter,
	params: {
		userId: string;
		accountId: string;
		partition: string;
		principalType: string;
		assumedRoleId?: string;
	},
) {
	let arn: string;
	if (params.assumedRoleId) {
		const role = await iamAdapter.findRoleById(params.assumedRoleId);
		const roleName = role ? (role as any).name : "unknown";
		arn = `arn:${params.partition}:sts::${params.accountId}:assumed-role/${roleName}`;
	} else {
		arn = `arn:${params.partition}:iam::${params.accountId}:user/${params.userId}`;
	}

	return {
		userId: params.userId,
		account: params.accountId,
		arn,
		principalType: params.principalType,
		assumedRoleId: params.assumedRoleId,
	};
}
