import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";

export async function setTags(
	iamAdapter: IamAdapter,
	resourceType: string,
	resourceId: string,
	tags: Record<string, string>,
	maxTagsPerResource: number,
) {
	const existing = await iamAdapter.listTags(resourceType, resourceId);
	const existingKeys = new Set(existing.map((t: any) => t.key));
	const newKeys = Object.keys(tags).filter((k) => !existingKeys.has(k));

	if (existing.length + newKeys.length > maxTagsPerResource) {
		throw new Error(IAM_ERROR_CODES.TAG_LIMIT_EXCEEDED.message);
	}

	for (const [key, value] of Object.entries(tags)) {
		if (key.length < 1 || key.length > 128) {
			throw new Error(IAM_ERROR_CODES.TAG_KEY_INVALID.message);
		}
		if (value.length > 256) {
			throw new Error(IAM_ERROR_CODES.TAG_VALUE_INVALID.message);
		}

		await iamAdapter.setTag({
			id: crypto.randomUUID(),
			resourceType,
			resourceId,
			key,
			value,
		});
	}
}

export async function removeTags(
	iamAdapter: IamAdapter,
	resourceType: string,
	resourceId: string,
	keys: string[],
) {
	for (const key of keys) {
		await iamAdapter.removeTag(resourceType, resourceId, key);
	}
}

export async function listTags(
	iamAdapter: IamAdapter,
	resourceType: string,
	resourceId: string,
) {
	return iamAdapter.listTags(resourceType, resourceId);
}

export async function getTagsAsMap(
	iamAdapter: IamAdapter,
	resourceType: string,
	resourceId: string,
): Promise<Record<string, string>> {
	return iamAdapter.getTagsAsMap(resourceType, resourceId);
}
