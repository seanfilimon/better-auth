import type { IamAdapter } from "../adapter";
import { createPolicySet, evaluate } from "../policy/engine";
import { buildVariableContext } from "../policy/variables";
import type {
	AuthorizationDecision,
	AuthorizationRequest,
	PolicyDocument,
} from "../types";

export async function simulatePolicy(
	iamAdapter: IamAdapter,
	params: {
		principalId: string;
		principalType: string;
		action: string;
		resource: string;
		contextEntries?: Record<string, unknown>;
		resourcePolicy?: PolicyDocument;
		permissionBoundary?: PolicyDocument;
		callerArn?: string;
		isRootUser?: boolean;
	},
): Promise<AuthorizationDecision> {
	const userAttachments = await iamAdapter.listAttachmentsByTarget(
		"user",
		params.principalId,
	);
	const groupMemberships = await iamAdapter.listUserGroups(params.principalId);
	const groupAttachments = await Promise.all(
		groupMemberships.map((gm: any) =>
			iamAdapter.listAttachmentsByTarget("group", gm.groupId),
		),
	);

	const allAttachmentIds = new Set([
		...userAttachments.map((a: any) => a.policyId),
		...groupAttachments.flat().map((a: any) => a.policyId),
	]);

	const identityDocs: PolicyDocument[] = [];
	for (const policyId of allAttachmentIds) {
		const policy = await iamAdapter.findPolicyById(policyId);
		if (!policy) continue;
		const policyData = policy as any;
		if (!policyData.defaultVersionId) continue;

		const version = await iamAdapter.findPolicyVersion(
			policyData.id,
			policyData.defaultVersionId,
		);
		if (!version) continue;

		const doc =
			typeof (version as any).document === "string"
				? JSON.parse((version as any).document)
				: (version as any).document;
		identityDocs.push(doc);
	}

	const boundaryDocs: PolicyDocument[] = [];
	if (params.permissionBoundary) {
		boundaryDocs.push(params.permissionBoundary);
	}

	const policySet = createPolicySet({
		identityPolicies: identityDocs,
		resourcePolicies: params.resourcePolicy ? [params.resourcePolicy] : [],
		permissionBoundaries: boundaryDocs,
	});

	const variableCtx = buildVariableContext({
		principalId: params.principalId,
		principalName: params.principalId,
		principalType: params.principalType,
	});

	const request: AuthorizationRequest = {
		principal: params.callerArn ?? params.principalId,
		principalType: params.principalType as any,
		action: params.action,
		resource: params.resource,
		context: { ...variableCtx, ...(params.contextEntries ?? {}) },
	};

	return evaluate(request, policySet, {
		isRootUser: params.isRootUser ?? false,
		variableContext: variableCtx,
	});
}
