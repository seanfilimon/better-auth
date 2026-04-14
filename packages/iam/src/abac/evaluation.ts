import type { IamAdapter } from "../adapter";
import { TAG_CONTEXT_KEY_PREFIXES } from "../constants";

export async function resolveABACContext(
	iamAdapter: IamAdapter,
	params: {
		principalId: string;
		principalType: string;
		resourceType?: string;
		resourceId?: string;
		requestTags?: Record<string, string>;
		sessionTags?: Record<string, string>;
	},
): Promise<Record<string, unknown>> {
	const context: Record<string, unknown> = {};

	const principalTags = await iamAdapter.getTagsAsMap(
		params.principalType.toLowerCase(),
		params.principalId,
	);
	for (const [k, v] of Object.entries(principalTags)) {
		context[`${TAG_CONTEXT_KEY_PREFIXES.PRINCIPAL_TAG}${k}`] = v;
	}

	if (params.resourceType && params.resourceId) {
		const resourceTags = await iamAdapter.getTagsAsMap(
			params.resourceType,
			params.resourceId,
		);
		for (const [k, v] of Object.entries(resourceTags)) {
			context[`${TAG_CONTEXT_KEY_PREFIXES.RESOURCE_TAG}${k}`] = v;
		}
	}

	if (params.requestTags) {
		for (const [k, v] of Object.entries(params.requestTags)) {
			context[`${TAG_CONTEXT_KEY_PREFIXES.REQUEST_TAG}${k}`] = v;
		}
	}

	if (params.sessionTags) {
		for (const [k, v] of Object.entries(params.sessionTags)) {
			context[`${TAG_CONTEXT_KEY_PREFIXES.PRINCIPAL_TAG}${k}`] = v;
		}
	}

	return context;
}
