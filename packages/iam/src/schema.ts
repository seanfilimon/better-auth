import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

export const schema = {
	user: {
		fields: {
			iamPath: {
				type: "string",
				required: false,
				defaultValue: "/",
			},
			isServiceAccount: {
				type: "boolean",
				required: false,
				defaultValue: false,
				input: false,
			},
			passwordLastUsed: {
				type: "date",
				required: false,
				input: false,
			},
			passwordLastChanged: {
				type: "date",
				required: false,
				input: false,
			},
		},
	},
	session: {
		fields: {
			iamRoleId: {
				type: "string",
				required: false,
			},
			iamSessionTags: {
				type: "json",
				required: false,
			},
			iamSourceIdentity: {
				type: "string",
				required: false,
			},
			iamSessionPolicyId: {
				type: "string",
				required: false,
			},
		},
	},
	iamPolicy: {
		fields: {
			name: {
				type: "string",
				required: true,
				sortable: true,
			},
			path: {
				type: "string",
				required: false,
				defaultValue: "/",
				index: true,
			},
			description: {
				type: "string",
				required: false,
			},
			type: {
				type: "string",
				required: true,
				index: true,
			},
			isServiceLinked: {
				type: "boolean",
				required: false,
				defaultValue: false,
			},
			defaultVersionId: {
				type: "string",
				required: false,
			},
			maxVersions: {
				type: "number",
				required: false,
				defaultValue: 5,
			},
			attachmentCount: {
				type: "number",
				required: false,
				defaultValue: 0,
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamPolicyVersion: {
		fields: {
			policyId: {
				type: "string",
				required: true,
				references: { model: "iamPolicy", field: "id" },
				index: true,
			},
			versionId: {
				type: "string",
				required: true,
				index: true,
			},
			document: {
				type: "json",
				required: true,
			},
			isDefault: {
				type: "boolean",
				required: true,
				defaultValue: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamRole: {
		fields: {
			name: {
				type: "string",
				required: true,
				unique: true,
				sortable: true,
			},
			path: {
				type: "string",
				required: false,
				defaultValue: "/",
				index: true,
			},
			description: {
				type: "string",
				required: false,
			},
			trustPolicy: {
				type: "json",
				required: true,
			},
			maxSessionDuration: {
				type: "number",
				required: false,
				defaultValue: 3600,
			},
			permissionBoundaryId: {
				type: "string",
				required: false,
			},
			isServiceLinked: {
				type: "boolean",
				required: false,
				defaultValue: false,
			},
			serviceLinkedService: {
				type: "string",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamGroup: {
		fields: {
			name: {
				type: "string",
				required: true,
				unique: true,
				sortable: true,
			},
			path: {
				type: "string",
				required: false,
				defaultValue: "/",
				index: true,
			},
			description: {
				type: "string",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamGroupMembership: {
		fields: {
			userId: {
				type: "string",
				required: true,
				references: { model: "user", field: "id" },
				index: true,
			},
			groupId: {
				type: "string",
				required: true,
				references: { model: "iamGroup", field: "id" },
				index: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamPolicyAttachment: {
		fields: {
			policyId: {
				type: "string",
				required: true,
				references: { model: "iamPolicy", field: "id" },
				index: true,
			},
			targetType: {
				type: "string",
				required: true,
				index: true,
			},
			targetId: {
				type: "string",
				required: true,
				index: true,
			},
			isInline: {
				type: "boolean",
				required: false,
				defaultValue: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamAccessKey: {
		fields: {
			secretKeyHash: {
				type: "string",
				required: true,
				returned: false,
			},
			userId: {
				type: "string",
				required: true,
				references: { model: "user", field: "id" },
				index: true,
			},
			status: {
				type: "string",
				required: true,
				defaultValue: "active",
			},
			lastUsedAt: {
				type: "date",
				required: false,
			},
			lastUsedService: {
				type: "string",
				required: false,
			},
			lastUsedRegion: {
				type: "string",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamServiceAccount: {
		fields: {
			name: {
				type: "string",
				required: true,
				unique: true,
				sortable: true,
			},
			description: {
				type: "string",
				required: false,
			},
			userId: {
				type: "string",
				required: true,
				references: { model: "user", field: "id" },
				index: true,
			},
			path: {
				type: "string",
				required: false,
				defaultValue: "/",
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamStsToken: {
		fields: {
			accessKeyId: {
				type: "string",
				required: true,
				index: true,
			},
			secretKeyHash: {
				type: "string",
				required: true,
				returned: false,
			},
			sessionToken: {
				type: "string",
				required: true,
				returned: false,
			},
			userId: {
				type: "string",
				required: true,
				references: { model: "user", field: "id" },
				index: true,
			},
			roleId: {
				type: "string",
				required: false,
				references: { model: "iamRole", field: "id" },
				index: true,
			},
			sessionPolicyDocument: {
				type: "json",
				required: false,
			},
			sessionTags: {
				type: "json",
				required: false,
			},
			transitiveTagKeys: {
				type: "json",
				required: false,
			},
			sourceIdentity: {
				type: "string",
				required: false,
			},
			expiresAt: {
				type: "date",
				required: true,
				index: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamFederationProvider: {
		fields: {
			name: {
				type: "string",
				required: true,
				unique: true,
				sortable: true,
			},
			type: {
				type: "string",
				required: true,
				index: true,
			},
			providerUrl: {
				type: "string",
				required: true,
			},
			clientId: {
				type: "string",
				required: false,
			},
			clientSecret: {
				type: "string",
				required: false,
				returned: false,
			},
			metadataDocument: {
				type: "json",
				required: false,
			},
			claimMapping: {
				type: "json",
				required: false,
			},
			thumbprints: {
				type: "json",
				required: false,
			},
			audiences: {
				type: "json",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamTrustPolicy: {
		fields: {
			roleId: {
				type: "string",
				required: true,
				references: { model: "iamRole", field: "id" },
				index: true,
			},
			principalType: {
				type: "string",
				required: true,
			},
			principalId: {
				type: "string",
				required: true,
			},
			conditions: {
				type: "json",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	iamTag: {
		fields: {
			resourceType: {
				type: "string",
				required: true,
				index: true,
			},
			resourceId: {
				type: "string",
				required: true,
				index: true,
			},
			key: {
				type: "string",
				required: true,
				index: true,
			},
			value: {
				type: "string",
				required: true,
			},
		},
	},
	iamAuditLog: {
		fields: {
			eventTime: {
				type: "date",
				required: true,
				index: true,
			},
			eventType: {
				type: "string",
				required: true,
				index: true,
			},
			eventSource: {
				type: "string",
				required: true,
			},
			principalId: {
				type: "string",
				required: true,
				index: true,
			},
			principalType: {
				type: "string",
				required: true,
			},
			action: {
				type: "string",
				required: true,
			},
			resource: {
				type: "string",
				required: false,
			},
			sourceIp: {
				type: "string",
				required: false,
			},
			userAgent: {
				type: "string",
				required: false,
			},
			requestParams: {
				type: "json",
				required: false,
			},
			responseStatus: {
				type: "string",
				required: true,
			},
			errorCode: {
				type: "string",
				required: false,
			},
			sessionId: {
				type: "string",
				required: false,
			},
			mfaAuthenticated: {
				type: "boolean",
				required: false,
				defaultValue: false,
			},
		},
	},
	iamAccountSettings: {
		fields: {
			accountId: {
				type: "string",
				required: true,
				unique: true,
				index: true,
			},
			accountAlias: {
				type: "string",
				required: false,
				unique: true,
			},
			passwordPolicy: {
				type: "json",
				required: false,
			},
			maxSessionDuration: {
				type: "number",
				required: false,
				defaultValue: 3600,
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
} satisfies BetterAuthPluginDBSchema;

export type IamSchema = typeof schema;
