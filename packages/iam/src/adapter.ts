import type { AuthContext } from "@better-auth/core";
import { getCurrentAdapter } from "@better-auth/core/context";
import type { PolicyDocument } from "./types";

export function getIamAdapter(context: AuthContext) {
	const baseAdapter = context.adapter;

	async function adapter() {
		return getCurrentAdapter(baseAdapter);
	}

	return {
		// ---- Policy ----
		async createPolicy(data: {
			id: string;
			name: string;
			path?: string;
			description?: string;
			type: string;
			isServiceLinked?: boolean;
			defaultVersionId?: string;
			maxVersions?: number;
		}) {
			const db = await adapter();
			const now = new Date();
			return db.create({
				model: "iamPolicy",
				data: {
					...data,
					path: data.path ?? "/",
					attachmentCount: 0,
					isServiceLinked: data.isServiceLinked ?? false,
					maxVersions: data.maxVersions ?? 5,
					createdAt: now,
					updatedAt: now,
				},
				forceAllowId: true,
			});
		},
		async findPolicyById(id: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamPolicy",
				where: [{ field: "id", value: id }],
			});
		},
		async findPolicyByName(name: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamPolicy",
				where: [{ field: "name", value: name }],
			});
		},
		async listPolicies(opts?: {
			type?: string;
			path?: string;
			limit?: number;
			offset?: number;
		}) {
			const db = await adapter();
			const where: any[] = [];
			if (opts?.type) where.push({ field: "type", value: opts.type });
			if (opts?.path) where.push({ field: "path", value: opts.path });
			return db.findMany({
				model: "iamPolicy",
				where,
				limit: opts?.limit,
				offset: opts?.offset,
			});
		},
		async updatePolicy(id: string, data: Record<string, unknown>) {
			const db = await adapter();
			return db.update({
				model: "iamPolicy",
				where: [{ field: "id", value: id }],
				update: { ...data, updatedAt: new Date() },
			});
		},
		async deletePolicy(id: string) {
			const db = await adapter();
			await db.delete({
				model: "iamPolicy",
				where: [{ field: "id", value: id }],
			});
		},

		// ---- Policy Version ----
		async createPolicyVersion(data: {
			id: string;
			policyId: string;
			versionId: string;
			document: PolicyDocument;
			isDefault: boolean;
		}) {
			const db = await adapter();
			return db.create({
				model: "iamPolicyVersion",
				data: {
					...data,
					document: JSON.stringify(data.document),
					createdAt: new Date(),
				},
				forceAllowId: true,
			});
		},
		async findPolicyVersion(policyId: string, versionId: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamPolicyVersion",
				where: [
					{ field: "policyId", value: policyId },
					{ field: "versionId", value: versionId },
				],
			});
		},
		async listPolicyVersions(policyId: string) {
			const db = await adapter();
			return db.findMany({
				model: "iamPolicyVersion",
				where: [{ field: "policyId", value: policyId }],
			});
		},
		async updatePolicyVersion(id: string, data: Record<string, unknown>) {
			const db = await adapter();
			return db.update({
				model: "iamPolicyVersion",
				where: [{ field: "id", value: id }],
				update: data,
			});
		},
		async deletePolicyVersionsByPolicy(policyId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamPolicyVersion",
				where: [{ field: "policyId", value: policyId }],
			});
		},
		async countPolicyVersions(policyId: string) {
			const db = await adapter();
			return db.count({
				model: "iamPolicyVersion",
				where: [{ field: "policyId", value: policyId }],
			});
		},

		// ---- Role ----
		async createRole(data: {
			id: string;
			name: string;
			path?: string;
			description?: string;
			trustPolicy: PolicyDocument;
			maxSessionDuration?: number;
			permissionBoundaryId?: string;
			isServiceLinked?: boolean;
			serviceLinkedService?: string;
		}) {
			const db = await adapter();
			const now = new Date();
			return db.create({
				model: "iamRole",
				data: {
					...data,
					path: data.path ?? "/",
					trustPolicy: JSON.stringify(data.trustPolicy),
					maxSessionDuration: data.maxSessionDuration ?? 3600,
					isServiceLinked: data.isServiceLinked ?? false,
					createdAt: now,
					updatedAt: now,
				},
				forceAllowId: true,
			});
		},
		async findRoleById(id: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamRole",
				where: [{ field: "id", value: id }],
			});
		},
		async findRoleByName(name: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamRole",
				where: [{ field: "name", value: name }],
			});
		},
		async listRoles(opts?: { path?: string; limit?: number; offset?: number }) {
			const db = await adapter();
			const where: any[] = [];
			if (opts?.path) where.push({ field: "path", value: opts.path });
			return db.findMany({
				model: "iamRole",
				where,
				limit: opts?.limit,
				offset: opts?.offset,
			});
		},
		async updateRole(id: string, data: Record<string, unknown>) {
			const db = await adapter();
			const update: Record<string, unknown> = {
				...data,
				updatedAt: new Date(),
			};
			if (update.trustPolicy && typeof update.trustPolicy === "object") {
				update.trustPolicy = JSON.stringify(update.trustPolicy);
			}
			return db.update({
				model: "iamRole",
				where: [{ field: "id", value: id }],
				update,
			});
		},
		async deleteRole(id: string) {
			const db = await adapter();
			await db.delete({
				model: "iamRole",
				where: [{ field: "id", value: id }],
			});
		},

		// ---- Group ----
		async createGroup(data: {
			id: string;
			name: string;
			path?: string;
			description?: string;
		}) {
			const db = await adapter();
			const now = new Date();
			return db.create({
				model: "iamGroup",
				data: {
					...data,
					path: data.path ?? "/",
					createdAt: now,
					updatedAt: now,
				},
				forceAllowId: true,
			});
		},
		async findGroupById(id: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamGroup",
				where: [{ field: "id", value: id }],
			});
		},
		async findGroupByName(name: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamGroup",
				where: [{ field: "name", value: name }],
			});
		},
		async listGroups(opts?: {
			path?: string;
			limit?: number;
			offset?: number;
		}) {
			const db = await adapter();
			const where: any[] = [];
			if (opts?.path) where.push({ field: "path", value: opts.path });
			return db.findMany({
				model: "iamGroup",
				where,
				limit: opts?.limit,
				offset: opts?.offset,
			});
		},
		async updateGroup(id: string, data: Record<string, unknown>) {
			const db = await adapter();
			return db.update({
				model: "iamGroup",
				where: [{ field: "id", value: id }],
				update: { ...data, updatedAt: new Date() },
			});
		},
		async deleteGroup(id: string) {
			const db = await adapter();
			await db.delete({
				model: "iamGroup",
				where: [{ field: "id", value: id }],
			});
		},

		// ---- Group Membership ----
		async addUserToGroup(data: {
			id: string;
			userId: string;
			groupId: string;
		}) {
			const db = await adapter();
			return db.create({
				model: "iamGroupMembership",
				data: { ...data, createdAt: new Date() },
				forceAllowId: true,
			});
		},
		async removeUserFromGroup(userId: string, groupId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamGroupMembership",
				where: [
					{ field: "userId", value: userId },
					{ field: "groupId", value: groupId },
				],
			});
		},
		async findMembership(userId: string, groupId: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamGroupMembership",
				where: [
					{ field: "userId", value: userId },
					{ field: "groupId", value: groupId },
				],
			});
		},
		async listGroupMembers(groupId: string) {
			const db = await adapter();
			return db.findMany({
				model: "iamGroupMembership",
				where: [{ field: "groupId", value: groupId }],
			});
		},
		async listUserGroups(userId: string) {
			const db = await adapter();
			return db.findMany({
				model: "iamGroupMembership",
				where: [{ field: "userId", value: userId }],
			});
		},
		async deleteGroupMemberships(groupId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamGroupMembership",
				where: [{ field: "groupId", value: groupId }],
			});
		},
		async deleteUserMemberships(userId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamGroupMembership",
				where: [{ field: "userId", value: userId }],
			});
		},

		// ---- Policy Attachment ----
		async attachPolicy(data: {
			id: string;
			policyId: string;
			targetType: string;
			targetId: string;
			isInline?: boolean;
		}) {
			const db = await adapter();
			return db.create({
				model: "iamPolicyAttachment",
				data: {
					...data,
					isInline: data.isInline ?? false,
					createdAt: new Date(),
				},
				forceAllowId: true,
			});
		},
		async detachPolicy(policyId: string, targetType: string, targetId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamPolicyAttachment",
				where: [
					{ field: "policyId", value: policyId },
					{ field: "targetType", value: targetType },
					{ field: "targetId", value: targetId },
				],
			});
		},
		async findAttachment(
			policyId: string,
			targetType: string,
			targetId: string,
		) {
			const db = await adapter();
			return db.findOne({
				model: "iamPolicyAttachment",
				where: [
					{ field: "policyId", value: policyId },
					{ field: "targetType", value: targetType },
					{ field: "targetId", value: targetId },
				],
			});
		},
		async listAttachmentsByTarget(targetType: string, targetId: string) {
			const db = await adapter();
			return db.findMany({
				model: "iamPolicyAttachment",
				where: [
					{ field: "targetType", value: targetType },
					{ field: "targetId", value: targetId },
				],
			});
		},
		async listAttachmentsByPolicy(policyId: string) {
			const db = await adapter();
			return db.findMany({
				model: "iamPolicyAttachment",
				where: [{ field: "policyId", value: policyId }],
			});
		},
		async countAttachmentsByPolicy(policyId: string) {
			const db = await adapter();
			return db.count({
				model: "iamPolicyAttachment",
				where: [{ field: "policyId", value: policyId }],
			});
		},
		async deleteAttachmentsByTarget(targetType: string, targetId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamPolicyAttachment",
				where: [
					{ field: "targetType", value: targetType },
					{ field: "targetId", value: targetId },
				],
			});
		},
		async deleteAttachmentsByPolicy(policyId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamPolicyAttachment",
				where: [{ field: "policyId", value: policyId }],
			});
		},

		// ---- Access Key ----
		async createAccessKey(data: {
			id: string;
			secretKeyHash: string;
			userId: string;
			status?: string;
		}) {
			const db = await adapter();
			return db.create({
				model: "iamAccessKey",
				data: {
					...data,
					status: data.status ?? "active",
					createdAt: new Date(),
				},
				forceAllowId: true,
			});
		},
		async findAccessKeyById(id: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamAccessKey",
				where: [{ field: "id", value: id }],
			});
		},
		async listAccessKeysByUser(userId: string) {
			const db = await adapter();
			return db.findMany({
				model: "iamAccessKey",
				where: [{ field: "userId", value: userId }],
			});
		},
		async updateAccessKey(id: string, data: Record<string, unknown>) {
			const db = await adapter();
			return db.update({
				model: "iamAccessKey",
				where: [{ field: "id", value: id }],
				update: data,
			});
		},
		async deleteAccessKey(id: string) {
			const db = await adapter();
			await db.delete({
				model: "iamAccessKey",
				where: [{ field: "id", value: id }],
			});
		},
		async deleteAccessKeysByUser(userId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamAccessKey",
				where: [{ field: "userId", value: userId }],
			});
		},
		async countAccessKeysByUser(userId: string) {
			const db = await adapter();
			return db.count({
				model: "iamAccessKey",
				where: [{ field: "userId", value: userId }],
			});
		},

		// ---- Service Account ----
		async createServiceAccount(data: {
			id: string;
			name: string;
			description?: string;
			userId: string;
			path?: string;
		}) {
			const db = await adapter();
			const now = new Date();
			return db.create({
				model: "iamServiceAccount",
				data: {
					...data,
					path: data.path ?? "/",
					createdAt: now,
					updatedAt: now,
				},
				forceAllowId: true,
			});
		},
		async findServiceAccountById(id: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamServiceAccount",
				where: [{ field: "id", value: id }],
			});
		},
		async findServiceAccountByName(name: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamServiceAccount",
				where: [{ field: "name", value: name }],
			});
		},
		async findServiceAccountByUserId(userId: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamServiceAccount",
				where: [{ field: "userId", value: userId }],
			});
		},
		async listServiceAccounts(opts?: { limit?: number; offset?: number }) {
			const db = await adapter();
			return db.findMany({
				model: "iamServiceAccount",
				where: [],
				limit: opts?.limit,
				offset: opts?.offset,
			});
		},
		async updateServiceAccount(id: string, data: Record<string, unknown>) {
			const db = await adapter();
			return db.update({
				model: "iamServiceAccount",
				where: [{ field: "id", value: id }],
				update: { ...data, updatedAt: new Date() },
			});
		},
		async deleteServiceAccount(id: string) {
			const db = await adapter();
			await db.delete({
				model: "iamServiceAccount",
				where: [{ field: "id", value: id }],
			});
		},

		// ---- STS Token ----
		async createStsToken(data: {
			id: string;
			accessKeyId: string;
			secretKeyHash: string;
			sessionToken: string;
			userId: string;
			roleId?: string;
			sessionPolicyDocument?: PolicyDocument;
			sessionTags?: Record<string, string>;
			transitiveTagKeys?: string[];
			sourceIdentity?: string;
			expiresAt: Date;
		}) {
			const db = await adapter();
			return db.create({
				model: "iamStsToken",
				data: {
					...data,
					sessionPolicyDocument: data.sessionPolicyDocument
						? JSON.stringify(data.sessionPolicyDocument)
						: undefined,
					sessionTags: data.sessionTags
						? JSON.stringify(data.sessionTags)
						: undefined,
					transitiveTagKeys: data.transitiveTagKeys
						? JSON.stringify(data.transitiveTagKeys)
						: undefined,
					createdAt: new Date(),
				},
				forceAllowId: true,
			});
		},
		async findStsTokenByAccessKeyId(accessKeyId: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamStsToken",
				where: [{ field: "accessKeyId", value: accessKeyId }],
			});
		},
		async findStsTokenById(id: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamStsToken",
				where: [{ field: "id", value: id }],
			});
		},
		async deleteStsToken(id: string) {
			const db = await adapter();
			await db.delete({
				model: "iamStsToken",
				where: [{ field: "id", value: id }],
			});
		},
		async deleteStsTokensByUser(userId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamStsToken",
				where: [{ field: "userId", value: userId }],
			});
		},
		async deleteExpiredStsTokens() {
			const db = await adapter();
			await db.deleteMany({
				model: "iamStsToken",
				where: [
					{ field: "expiresAt", value: new Date(), operator: "lt" as any },
				],
			});
		},

		// ---- Federation Provider ----
		async createFederationProvider(data: {
			id: string;
			name: string;
			type: string;
			providerUrl: string;
			clientId?: string;
			clientSecret?: string;
			metadataDocument?: unknown;
			claimMapping?: unknown;
			thumbprints?: string[];
			audiences?: string[];
		}) {
			const db = await adapter();
			const now = new Date();
			return db.create({
				model: "iamFederationProvider",
				data: {
					...data,
					metadataDocument: data.metadataDocument
						? JSON.stringify(data.metadataDocument)
						: undefined,
					claimMapping: data.claimMapping
						? JSON.stringify(data.claimMapping)
						: undefined,
					thumbprints: data.thumbprints
						? JSON.stringify(data.thumbprints)
						: undefined,
					audiences: data.audiences
						? JSON.stringify(data.audiences)
						: undefined,
					createdAt: now,
					updatedAt: now,
				},
				forceAllowId: true,
			});
		},
		async findFederationProviderById(id: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamFederationProvider",
				where: [{ field: "id", value: id }],
			});
		},
		async findFederationProviderByName(name: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamFederationProvider",
				where: [{ field: "name", value: name }],
			});
		},
		async listFederationProviders(opts?: {
			type?: string;
			limit?: number;
			offset?: number;
		}) {
			const db = await adapter();
			const where: any[] = [];
			if (opts?.type) where.push({ field: "type", value: opts.type });
			return db.findMany({
				model: "iamFederationProvider",
				where,
				limit: opts?.limit,
				offset: opts?.offset,
			});
		},
		async updateFederationProvider(id: string, data: Record<string, unknown>) {
			const db = await adapter();
			const update: Record<string, unknown> = {
				...data,
				updatedAt: new Date(),
			};
			for (const key of [
				"metadataDocument",
				"claimMapping",
				"thumbprints",
				"audiences",
			]) {
				if (update[key] && typeof update[key] === "object") {
					update[key] = JSON.stringify(update[key]);
				}
			}
			return db.update({
				model: "iamFederationProvider",
				where: [{ field: "id", value: id }],
				update,
			});
		},
		async deleteFederationProvider(id: string) {
			const db = await adapter();
			await db.delete({
				model: "iamFederationProvider",
				where: [{ field: "id", value: id }],
			});
		},

		// ---- Trust Policy ----
		async createTrustPolicy(data: {
			id: string;
			roleId: string;
			principalType: string;
			principalId: string;
			conditions?: unknown;
		}) {
			const db = await adapter();
			return db.create({
				model: "iamTrustPolicy",
				data: {
					...data,
					conditions: data.conditions
						? JSON.stringify(data.conditions)
						: undefined,
					createdAt: new Date(),
				},
				forceAllowId: true,
			});
		},
		async listTrustPoliciesByRole(roleId: string) {
			const db = await adapter();
			return db.findMany({
				model: "iamTrustPolicy",
				where: [{ field: "roleId", value: roleId }],
			});
		},
		async deleteTrustPoliciesByRole(roleId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamTrustPolicy",
				where: [{ field: "roleId", value: roleId }],
			});
		},

		// ---- Tags ----
		async setTag(data: {
			id: string;
			resourceType: string;
			resourceId: string;
			key: string;
			value: string;
		}) {
			const db = await adapter();
			const existing = await db.findOne({
				model: "iamTag",
				where: [
					{ field: "resourceType", value: data.resourceType },
					{ field: "resourceId", value: data.resourceId },
					{ field: "key", value: data.key },
				],
			});
			if (existing) {
				return db.update({
					model: "iamTag",
					where: [{ field: "id", value: (existing as any).id }],
					update: { value: data.value },
				});
			}
			return db.create({ model: "iamTag", data, forceAllowId: true });
		},
		async removeTag(resourceType: string, resourceId: string, key: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamTag",
				where: [
					{ field: "resourceType", value: resourceType },
					{ field: "resourceId", value: resourceId },
					{ field: "key", value: key },
				],
			});
		},
		async listTags(resourceType: string, resourceId: string) {
			const db = await adapter();
			return db.findMany({
				model: "iamTag",
				where: [
					{ field: "resourceType", value: resourceType },
					{ field: "resourceId", value: resourceId },
				],
			});
		},
		async deleteTagsByResource(resourceType: string, resourceId: string) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamTag",
				where: [
					{ field: "resourceType", value: resourceType },
					{ field: "resourceId", value: resourceId },
				],
			});
		},
		async getTagsAsMap(
			resourceType: string,
			resourceId: string,
		): Promise<Record<string, string>> {
			const tags = await this.listTags(resourceType, resourceId);
			const map: Record<string, string> = {};
			for (const t of tags as any[]) {
				map[t.key] = t.value;
			}
			return map;
		},

		// ---- Audit Log ----
		async createAuditLog(data: {
			id: string;
			eventTime: Date;
			eventType: string;
			eventSource: string;
			principalId: string;
			principalType: string;
			action: string;
			resource?: string;
			sourceIp?: string;
			userAgent?: string;
			requestParams?: Record<string, unknown>;
			responseStatus: string;
			errorCode?: string;
			sessionId?: string;
			mfaAuthenticated?: boolean;
		}) {
			const db = await adapter();
			return db.create({
				model: "iamAuditLog",
				data: {
					...data,
					requestParams: data.requestParams
						? JSON.stringify(data.requestParams)
						: undefined,
					mfaAuthenticated: data.mfaAuthenticated ?? false,
				},
				forceAllowId: true,
			});
		},
		async queryAuditLogs(filters: {
			eventType?: string;
			principalId?: string;
			action?: string;
			resource?: string;
			startTime?: Date;
			endTime?: Date;
			responseStatus?: string;
			limit?: number;
			offset?: number;
		}) {
			const db = await adapter();
			const where: any[] = [];
			if (filters.eventType)
				where.push({ field: "eventType", value: filters.eventType });
			if (filters.principalId)
				where.push({ field: "principalId", value: filters.principalId });
			if (filters.action)
				where.push({ field: "action", value: filters.action });
			if (filters.responseStatus)
				where.push({ field: "responseStatus", value: filters.responseStatus });
			if (filters.startTime)
				where.push({
					field: "eventTime",
					value: filters.startTime,
					operator: "gte" as any,
				});
			if (filters.endTime)
				where.push({
					field: "eventTime",
					value: filters.endTime,
					operator: "lte" as any,
				});
			return db.findMany({
				model: "iamAuditLog",
				where,
				limit: filters.limit ?? 100,
				offset: filters.offset,
				sortBy: { field: "eventTime", direction: "desc" },
			});
		},
		async deleteAuditLogsBefore(date: Date) {
			const db = await adapter();
			await db.deleteMany({
				model: "iamAuditLog",
				where: [{ field: "eventTime", value: date, operator: "lt" as any }],
			});
		},

		// ---- Account Settings ----
		async getAccountSettings(accountId: string) {
			const db = await adapter();
			return db.findOne({
				model: "iamAccountSettings",
				where: [{ field: "accountId", value: accountId }],
			});
		},
		async upsertAccountSettings(data: {
			id: string;
			accountId: string;
			accountAlias?: string;
			passwordPolicy?: unknown;
			maxSessionDuration?: number;
		}) {
			const db = await adapter();
			const existing = await db.findOne({
				model: "iamAccountSettings",
				where: [{ field: "accountId", value: data.accountId }],
			});
			const now = new Date();
			if (existing) {
				const update: Record<string, unknown> = { updatedAt: now };
				if (data.accountAlias !== undefined)
					update.accountAlias = data.accountAlias;
				if (data.passwordPolicy !== undefined)
					update.passwordPolicy = JSON.stringify(data.passwordPolicy);
				if (data.maxSessionDuration !== undefined)
					update.maxSessionDuration = data.maxSessionDuration;
				return db.update({
					model: "iamAccountSettings",
					where: [{ field: "id", value: (existing as any).id }],
					update,
				});
			}
			return db.create({
				model: "iamAccountSettings",
				data: {
					...data,
					passwordPolicy: data.passwordPolicy
						? JSON.stringify(data.passwordPolicy)
						: undefined,
					createdAt: now,
					updatedAt: now,
				},
				forceAllowId: true,
			});
		},
	};
}

export type IamAdapter = ReturnType<typeof getIamAdapter>;
