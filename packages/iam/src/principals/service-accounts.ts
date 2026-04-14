import type { AuthContext } from "@better-auth/core";
import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";

export async function createServiceAccount(
	ctx: AuthContext,
	iamAdapter: IamAdapter,
	data: {
		id: string;
		name: string;
		description?: string;
		path?: string;
	},
) {
	const existing = await iamAdapter.findServiceAccountByName(data.name);
	if (existing) {
		throw new Error(IAM_ERROR_CODES.SERVICE_ACCOUNT_ALREADY_EXISTS.message);
	}

	const email = `${data.name}@service.iam.internal`;
	const user = await ctx.internalAdapter.createUser({
		name: data.name,
		email,
		emailVerified: true,
	});
	if (!user) {
		throw new Error(IAM_ERROR_CODES.INTERNAL_ERROR.message);
	}

	await ctx.internalAdapter.updateUser(user.id, {
		isServiceAccount: true,
	} as any);

	const sa = await iamAdapter.createServiceAccount({
		id: data.id,
		name: data.name,
		description: data.description,
		userId: user.id,
		path: data.path,
	});

	return { serviceAccount: sa, userId: user.id };
}

export async function getServiceAccount(
	iamAdapter: IamAdapter,
	serviceAccountId: string,
) {
	return iamAdapter.findServiceAccountById(serviceAccountId);
}

export async function listServiceAccounts(
	iamAdapter: IamAdapter,
	opts?: { limit?: number; offset?: number },
) {
	return iamAdapter.listServiceAccounts(opts);
}

export async function updateServiceAccount(
	iamAdapter: IamAdapter,
	serviceAccountId: string,
	data: { name?: string; description?: string },
) {
	const sa = await iamAdapter.findServiceAccountById(serviceAccountId);
	if (!sa) {
		throw new Error(IAM_ERROR_CODES.SERVICE_ACCOUNT_NOT_FOUND.message);
	}
	if (data.name && data.name !== (sa as any).name) {
		const existing = await iamAdapter.findServiceAccountByName(data.name);
		if (existing) {
			throw new Error(IAM_ERROR_CODES.SERVICE_ACCOUNT_ALREADY_EXISTS.message);
		}
	}
	return iamAdapter.updateServiceAccount(serviceAccountId, data);
}

export async function deleteServiceAccount(
	ctx: AuthContext,
	iamAdapter: IamAdapter,
	serviceAccountId: string,
) {
	const sa = await iamAdapter.findServiceAccountById(serviceAccountId);
	if (!sa) {
		throw new Error(IAM_ERROR_CODES.SERVICE_ACCOUNT_NOT_FOUND.message);
	}
	const userId = (sa as any).userId;

	await iamAdapter.deleteAccessKeysByUser(userId);
	await iamAdapter.deleteStsTokensByUser(userId);
	await iamAdapter.deleteAttachmentsByTarget("user", userId);
	await iamAdapter.deleteUserMemberships(userId);
	await iamAdapter.deleteTagsByResource("serviceAccount", serviceAccountId);
	await iamAdapter.deleteServiceAccount(serviceAccountId);
	await ctx.internalAdapter.deleteUser(userId);
}
