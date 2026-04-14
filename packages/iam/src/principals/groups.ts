import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";

export async function createGroup(
	iamAdapter: IamAdapter,
	data: { id: string; name: string; path?: string; description?: string },
) {
	const existing = await iamAdapter.findGroupByName(data.name);
	if (existing) {
		throw new Error(IAM_ERROR_CODES.GROUP_ALREADY_EXISTS.message);
	}
	return iamAdapter.createGroup(data);
}

export async function getGroup(iamAdapter: IamAdapter, groupId: string) {
	return iamAdapter.findGroupById(groupId);
}

export async function listGroups(
	iamAdapter: IamAdapter,
	opts?: { path?: string; limit?: number; offset?: number },
) {
	return iamAdapter.listGroups(opts);
}

export async function updateGroup(
	iamAdapter: IamAdapter,
	groupId: string,
	data: { name?: string; path?: string; description?: string },
) {
	const group = await iamAdapter.findGroupById(groupId);
	if (!group) {
		throw new Error(IAM_ERROR_CODES.GROUP_NOT_FOUND.message);
	}
	if (data.name && data.name !== group.name) {
		const existing = await iamAdapter.findGroupByName(data.name);
		if (existing) {
			throw new Error(IAM_ERROR_CODES.GROUP_ALREADY_EXISTS.message);
		}
	}
	return iamAdapter.updateGroup(groupId, data);
}

export async function deleteGroup(iamAdapter: IamAdapter, groupId: string) {
	const group = await iamAdapter.findGroupById(groupId);
	if (!group) {
		throw new Error(IAM_ERROR_CODES.GROUP_NOT_FOUND.message);
	}
	await iamAdapter.deleteGroupMemberships(groupId);
	await iamAdapter.deleteAttachmentsByTarget("group", groupId);
	await iamAdapter.deleteTagsByResource("group", groupId);
	await iamAdapter.deleteGroup(groupId);
}

export async function addUserToGroup(
	iamAdapter: IamAdapter,
	data: { id: string; userId: string; groupId: string },
	maxGroupsPerUser: number,
) {
	const group = await iamAdapter.findGroupById(data.groupId);
	if (!group) {
		throw new Error(IAM_ERROR_CODES.GROUP_NOT_FOUND.message);
	}

	const existing = await iamAdapter.findMembership(data.userId, data.groupId);
	if (existing) {
		throw new Error(IAM_ERROR_CODES.USER_ALREADY_IN_GROUP.message);
	}

	const userGroups = await iamAdapter.listUserGroups(data.userId);
	if (userGroups.length >= maxGroupsPerUser) {
		throw new Error(IAM_ERROR_CODES.GROUP_MEMBERSHIP_LIMIT_EXCEEDED.message);
	}

	return iamAdapter.addUserToGroup(data);
}

export async function removeUserFromGroup(
	iamAdapter: IamAdapter,
	userId: string,
	groupId: string,
) {
	const existing = await iamAdapter.findMembership(userId, groupId);
	if (!existing) {
		throw new Error(IAM_ERROR_CODES.USER_NOT_IN_GROUP.message);
	}
	await iamAdapter.removeUserFromGroup(userId, groupId);
}
