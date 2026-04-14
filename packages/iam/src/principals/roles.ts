import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";
import type { PolicyDocument } from "../types";

export async function createRole(
	iamAdapter: IamAdapter,
	data: {
		id: string;
		name: string;
		path?: string;
		description?: string;
		trustPolicy: PolicyDocument;
		maxSessionDuration?: number;
		permissionBoundaryId?: string;
		isServiceLinked?: boolean;
		serviceLinkedService?: string;
	},
) {
	const existing = await iamAdapter.findRoleByName(data.name);
	if (existing) {
		throw new Error(IAM_ERROR_CODES.ROLE_ALREADY_EXISTS.message);
	}
	return iamAdapter.createRole(data);
}

export async function getRole(iamAdapter: IamAdapter, roleId: string) {
	return iamAdapter.findRoleById(roleId);
}

export async function listRoles(
	iamAdapter: IamAdapter,
	opts?: { path?: string; limit?: number; offset?: number },
) {
	return iamAdapter.listRoles(opts);
}

export async function updateRole(
	iamAdapter: IamAdapter,
	roleId: string,
	data: {
		name?: string;
		description?: string;
		maxSessionDuration?: number;
		permissionBoundaryId?: string;
	},
) {
	const role = await iamAdapter.findRoleById(roleId);
	if (!role) {
		throw new Error(IAM_ERROR_CODES.ROLE_NOT_FOUND.message);
	}
	if ((role as any).isServiceLinked) {
		throw new Error(IAM_ERROR_CODES.SERVICE_LINKED_ROLE_PROTECTED.message);
	}
	if (data.name && data.name !== (role as any).name) {
		const existing = await iamAdapter.findRoleByName(data.name);
		if (existing) {
			throw new Error(IAM_ERROR_CODES.ROLE_ALREADY_EXISTS.message);
		}
	}
	return iamAdapter.updateRole(roleId, data);
}

export async function deleteRole(iamAdapter: IamAdapter, roleId: string) {
	const role = await iamAdapter.findRoleById(roleId);
	if (!role) {
		throw new Error(IAM_ERROR_CODES.ROLE_NOT_FOUND.message);
	}
	if ((role as any).isServiceLinked) {
		throw new Error(IAM_ERROR_CODES.SERVICE_LINKED_ROLE_PROTECTED.message);
	}
	await iamAdapter.deleteAttachmentsByTarget("role", roleId);
	await iamAdapter.deleteTrustPoliciesByRole(roleId);
	await iamAdapter.deleteTagsByResource("role", roleId);
	await iamAdapter.deleteRole(roleId);
}

export async function updateTrustPolicy(
	iamAdapter: IamAdapter,
	roleId: string,
	trustPolicy: PolicyDocument,
) {
	const role = await iamAdapter.findRoleById(roleId);
	if (!role) {
		throw new Error(IAM_ERROR_CODES.ROLE_NOT_FOUND.message);
	}
	if ((role as any).isServiceLinked) {
		throw new Error(IAM_ERROR_CODES.SERVICE_LINKED_ROLE_PROTECTED.message);
	}
	return iamAdapter.updateRole(roleId, { trustPolicy });
}

export async function getRoleEffectivePolicies(
	iamAdapter: IamAdapter,
	roleId: string,
) {
	const attachments = await iamAdapter.listAttachmentsByTarget("role", roleId);
	const policyIds = [
		...new Set(attachments.map((a: any) => a.policyId as string)),
	];
	const policies = await Promise.all(
		policyIds.map((id) => iamAdapter.findPolicyById(id)),
	);
	return policies.filter(Boolean);
}
