import type { IamQuotas, PasswordPolicy } from "./types";

export const IAM_PLUGIN_ID = "iam" as const;

export const POLICY_VERSION = "2024-01-01";

export const DEFAULT_PARTITION = "auth";

export const ACCESS_KEY_PREFIX_LONG_TERM = "AKIA";
export const ACCESS_KEY_PREFIX_TEMPORARY = "ASIA";
export const ACCESS_KEY_ID_LENGTH = 20;
export const SECRET_KEY_LENGTH = 40;
export const SESSION_TOKEN_LENGTH = 64;

export const ARN_SEPARATOR = ":";
export const ARN_PREFIX = "arn";
export const ARN_WILDCARD = "*";
export const ARN_QUESTION_MARK = "?";

export const DEFAULT_QUOTAS: IamQuotas = {
	maxUsersPerAccount: 5000,
	maxGroupsPerAccount: 300,
	maxRolesPerAccount: 1000,
	maxPoliciesPerAccount: 1500,
	maxPolicyVersions: 5,
	maxAccessKeysPerUser: 2,
	maxGroupsPerUser: 10,
	maxPoliciesPerEntity: 10,
	maxInlinePoliciesPerEntity: 5,
	maxTagsPerResource: 50,
};

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
	minLength: 14,
	requireUppercase: true,
	requireLowercase: true,
	requireNumbers: true,
	requireSymbols: true,
	maxAgeDays: 90,
	preventReuseCount: 24,
};

export const DEFAULT_STS_DURATION = 3600;
export const MAX_STS_DURATION = 43200;
export const DEFAULT_MAX_SESSION_DURATION = 3600;

export const DEFAULT_AUDIT_RETENTION_DAYS = 90;

export const CONDITION_OPERATORS = [
	"StringEquals",
	"StringNotEquals",
	"StringEqualsIgnoreCase",
	"StringNotEqualsIgnoreCase",
	"StringLike",
	"StringNotLike",
	"NumericEquals",
	"NumericNotEquals",
	"NumericLessThan",
	"NumericLessThanEquals",
	"NumericGreaterThan",
	"NumericGreaterThanEquals",
	"DateEquals",
	"DateNotEquals",
	"DateLessThan",
	"DateLessThanEquals",
	"DateGreaterThan",
	"DateGreaterThanEquals",
	"Bool",
	"IpAddress",
	"NotIpAddress",
	"ArnEquals",
	"ArnNotEquals",
	"ArnLike",
	"ArnNotLike",
	"Null",
] as const;

export type ConditionOperator = (typeof CONDITION_OPERATORS)[number];

export const CONDITION_MODIFIER_PREFIXES = [
	"ForAllValues:",
	"ForAnyValue:",
] as const;

export const CONDITION_IF_EXISTS_SUFFIX = "IfExists";

export const GLOBAL_CONTEXT_KEYS = {
	CURRENT_TIME: "iam:CurrentTime",
	EPOCH_TIME: "iam:EpochTime",
	SECURE_TRANSPORT: "iam:SecureTransport",
	SOURCE_IP: "iam:SourceIp",
	USER_AGENT: "iam:UserAgent",
	MFA_PRESENT: "iam:MultiFactorAuthPresent",
	MFA_AGE: "iam:MultiFactorAuthAge",
	PRINCIPAL_ORG_ID: "iam:PrincipalOrgID",
	PRINCIPAL_TYPE: "iam:PrincipalType",
	PRINCIPAL_IS_SERVICE_ACCOUNT: "iam:PrincipalIsServiceAccount",
	PRINCIPAL_IS_ANONYMOUS: "iam:PrincipalIsAnonymous",
} as const;

export const TAG_CONTEXT_KEY_PREFIXES = {
	PRINCIPAL_TAG: "iam:PrincipalTag/",
	RESOURCE_TAG: "iam:ResourceTag/",
	REQUEST_TAG: "iam:RequestTag/",
} as const;

export const POLICY_VARIABLES: Record<string, string> = {
	"iam:username": "principalName",
	"iam:userid": "principalId",
	"iam:principaltype": "principalType",
	"iam:sourceidentity": "sourceIdentity",
	"iam:currenttime": "currentTime",
	"iam:epochtime": "epochTime",
	"iam:securetransport": "secureTransport",
	"iam:sourceip": "sourceIp",
	"iam:useragent": "userAgent",
	"auth:orgid": "orgId",
	"auth:teamid": "teamId",
};

export const IAM_ACTIONS = {
	CREATE_USER: "iam:CreateUser",
	UPDATE_USER: "iam:UpdateUser",
	DELETE_USER: "iam:DeleteUser",
	GET_USER: "iam:GetUser",
	LIST_USERS: "iam:ListUsers",
	LIST_USER_POLICIES: "iam:ListUserPolicies",

	CREATE_GROUP: "iam:CreateGroup",
	UPDATE_GROUP: "iam:UpdateGroup",
	DELETE_GROUP: "iam:DeleteGroup",
	GET_GROUP: "iam:GetGroup",
	LIST_GROUPS: "iam:ListGroups",
	ADD_USER_TO_GROUP: "iam:AddUserToGroup",
	REMOVE_USER_FROM_GROUP: "iam:RemoveUserFromGroup",

	CREATE_ROLE: "iam:CreateRole",
	UPDATE_ROLE: "iam:UpdateRole",
	DELETE_ROLE: "iam:DeleteRole",
	GET_ROLE: "iam:GetRole",
	LIST_ROLES: "iam:ListRoles",
	UPDATE_TRUST_POLICY: "iam:UpdateAssumeRolePolicy",

	CREATE_POLICY: "iam:CreatePolicy",
	UPDATE_POLICY: "iam:UpdatePolicy",
	DELETE_POLICY: "iam:DeletePolicy",
	GET_POLICY: "iam:GetPolicy",
	LIST_POLICIES: "iam:ListPolicies",
	CREATE_POLICY_VERSION: "iam:CreatePolicyVersion",
	SET_DEFAULT_POLICY_VERSION: "iam:SetDefaultPolicyVersion",
	LIST_POLICY_VERSIONS: "iam:ListPolicyVersions",
	ATTACH_POLICY: "iam:AttachUserPolicy",
	DETACH_POLICY: "iam:DetachUserPolicy",
	LIST_ATTACHMENTS: "iam:ListAttachedPolicies",

	CREATE_ACCESS_KEY: "iam:CreateAccessKey",
	DELETE_ACCESS_KEY: "iam:DeleteAccessKey",
	UPDATE_ACCESS_KEY: "iam:UpdateAccessKey",
	LIST_ACCESS_KEYS: "iam:ListAccessKeys",
	GET_ACCESS_KEY_LAST_USED: "iam:GetAccessKeyLastUsed",

	CREATE_SERVICE_ACCOUNT: "iam:CreateServiceAccount",
	UPDATE_SERVICE_ACCOUNT: "iam:UpdateServiceAccount",
	DELETE_SERVICE_ACCOUNT: "iam:DeleteServiceAccount",
	GET_SERVICE_ACCOUNT: "iam:GetServiceAccount",
	LIST_SERVICE_ACCOUNTS: "iam:ListServiceAccounts",

	ASSUME_ROLE: "sts:AssumeRole",
	GET_SESSION_TOKEN: "sts:GetSessionToken",
	ASSUME_ROLE_WITH_WEB_IDENTITY: "sts:AssumeRoleWithWebIdentity",
	ASSUME_ROLE_WITH_SAML: "sts:AssumeRoleWithSAML",
	GET_CALLER_IDENTITY: "sts:GetCallerIdentity",

	CREATE_FEDERATION_PROVIDER: "iam:CreateOpenIDConnectProvider",
	UPDATE_FEDERATION_PROVIDER: "iam:UpdateOpenIDConnectProvider",
	DELETE_FEDERATION_PROVIDER: "iam:DeleteOpenIDConnectProvider",
	GET_FEDERATION_PROVIDER: "iam:GetOpenIDConnectProvider",
	LIST_FEDERATION_PROVIDERS: "iam:ListOpenIDConnectProviders",

	SET_TAGS: "iam:TagResource",
	REMOVE_TAGS: "iam:UntagResource",
	LIST_TAGS: "iam:ListResourceTags",

	QUERY_AUDIT: "iam:GetAuditLogs",
	CREDENTIAL_REPORT: "iam:GenerateCredentialReport",
	ACCESS_REPORT: "iam:GetAccessReport",
	CLEANUP_AUDIT: "iam:CleanupAuditLogs",

	VALIDATE_POLICY: "iam:ValidatePolicy",
	SIMULATE_POLICY: "iam:SimulateCustomPolicy",
	ANALYZE_ACCESS: "iam:GetAccessAnalysis",
	UNUSED_ACCESS: "iam:GetUnusedAccess",

	GET_ACCOUNT_SETTINGS: "iam:GetAccountSettings",
	UPDATE_ACCOUNT_SETTINGS: "iam:UpdateAccountSettings",
} as const;

export const SIGNING_ALGORITHM = "IAM-HMAC-SHA256";
export const SIGNING_HEADER_PREFIX = "IAM-HMAC";

export const REDACTED_FIELDS_DEFAULT = [
	"password",
	"secretKey",
	"secretAccessKey",
	"secretKeyHash",
	"sessionToken",
	"sessionTokenHash",
	"clientSecret",
	"token",
	"samlResponse",
	"externalId",
];
