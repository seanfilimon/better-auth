import type { AuthContext } from "@better-auth/core";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";

export async function createIamUser(
	ctx: AuthContext,
	iamAdapter: IamAdapter,
	data: { name: string; email: string; password?: string; iamPath?: string },
) {
	const user = await ctx.internalAdapter.createUser({
		name: data.name,
		email: data.email,
		emailVerified: false,
	});
	if (!user) {
		throw new Error(IAM_ERROR_CODES.INTERNAL_ERROR.message);
	}

	if (data.iamPath && data.iamPath !== "/") {
		await ctx.internalAdapter.updateUser(user.id, {
			iamPath: data.iamPath,
		} as any);
	}

	return user;
}

export async function getIamUser(ctx: AuthContext, userId: string) {
	const user = await ctx.internalAdapter.findUserById(userId);
	if (!user) return null;
	return user;
}

export async function listIamUsers(
	ctx: AuthContext,
	opts?: { limit?: number; offset?: number },
) {
	const users = await ctx.internalAdapter.listUsers(opts?.limit, opts?.offset);
	return users;
}

export async function updateIamUser(
	ctx: AuthContext,
	userId: string,
	data: { name?: string; iamPath?: string },
) {
	const updated = await ctx.internalAdapter.updateUser(userId, data as any);
	return updated;
}

export async function deleteIamUser(
	ctx: AuthContext,
	iamAdapter: IamAdapter,
	userId: string,
) {
	await iamAdapter.deleteUserMemberships(userId);
	await iamAdapter.deleteAttachmentsByTarget("user", userId);
	await iamAdapter.deleteAccessKeysByUser(userId);
	await iamAdapter.deleteStsTokensByUser(userId);
	await iamAdapter.deleteTagsByResource("user", userId);
	await ctx.internalAdapter.deleteUser(userId);
}

export async function listUserEffectivePolicies(
	iamAdapter: IamAdapter,
	userId: string,
) {
	const directAttachments = await iamAdapter.listAttachmentsByTarget(
		"user",
		userId,
	);

	const groupMemberships = await iamAdapter.listUserGroups(userId);
	const groupAttachments = await Promise.all(
		groupMemberships.map((gm: any) =>
			iamAdapter.listAttachmentsByTarget("group", gm.groupId),
		),
	);

	const allAttachments = [...directAttachments, ...groupAttachments.flat()];

	const policyIds = [...new Set(allAttachments.map((a: any) => a.policyId))];

	const policies = await Promise.all(
		policyIds.map((id) => iamAdapter.findPolicyById(id)),
	);

	return policies.filter(Boolean);
}

export async function listUserEffectivePolicyDocuments(
	iamAdapter: IamAdapter,
	userId: string,
): Promise<Array<{ policyId: string; policyName: string; document: unknown }>> {
	const policies = await listUserEffectivePolicies(iamAdapter, userId);
	const docs: Array<{
		policyId: string;
		policyName: string;
		document: unknown;
	}> = [];

	for (const policy of policies) {
		const policyData = policy as any;
		if (!policyData.defaultVersionId) continue;

		const version = await iamAdapter.findPolicyVersion(
			policyData.id,
			policyData.defaultVersionId,
		);
		if (!version) continue;

		let doc: Record<string, unknown> | undefined;
		try {
			doc =
				typeof (version as any).document === "string"
					? JSON.parse((version as any).document)
					: (version as any).document;
		} catch {
			continue;
		}

		if (doc) {
			docs.push({
				policyId: policyData.id,
				policyName: policyData.name,
				document: doc,
			});
		}
	}

	return docs;
}
