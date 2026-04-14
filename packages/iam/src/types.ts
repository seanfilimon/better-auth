export type Effect = "Allow" | "Deny";

export type PrincipalMap = Record<string, string | string[]>;

export interface ConditionBlock {
	[operator: string]: Record<string, string | string[] | number | boolean>;
}

export interface PolicyStatement {
	Sid?: string;
	Effect: Effect;
	Action?: string | string[];
	NotAction?: string | string[];
	Resource?: string | string[];
	NotResource?: string | string[];
	Principal?: "*" | PrincipalMap;
	NotPrincipal?: PrincipalMap;
	Condition?: ConditionBlock;
}

export interface PolicyDocument {
	Version: string;
	Id?: string;
	Statement: PolicyStatement[];
}

export interface ParsedARN {
	partition: string;
	service: string;
	region: string;
	account: string;
	resourceType: string;
	resourcePath: string;
}

export type PrincipalType =
	| "User"
	| "Role"
	| "Group"
	| "Service"
	| "FederatedUser"
	| "Anonymous"
	| "Root";

export type PolicyType =
	| "managed"
	| "inline"
	| "boundary"
	| "resource"
	| "session";

export type AccessKeyStatus = "active" | "inactive";

export type AccessKeyPrefix = "AKIA" | "ASIA";

export type AuditEventType =
	| "CreateUser"
	| "UpdateUser"
	| "DeleteUser"
	| "CreateGroup"
	| "UpdateGroup"
	| "DeleteGroup"
	| "AddUserToGroup"
	| "RemoveUserFromGroup"
	| "CreateRole"
	| "UpdateRole"
	| "DeleteRole"
	| "UpdateTrustPolicy"
	| "CreatePolicy"
	| "UpdatePolicy"
	| "DeletePolicy"
	| "CreatePolicyVersion"
	| "SetDefaultPolicyVersion"
	| "AttachPolicy"
	| "DetachPolicy"
	| "CreateAccessKey"
	| "DeleteAccessKey"
	| "UpdateAccessKeyStatus"
	| "CreateServiceAccount"
	| "UpdateServiceAccount"
	| "DeleteServiceAccount"
	| "AssumeRole"
	| "GetSessionToken"
	| "AssumeRoleWithWebIdentity"
	| "AssumeRoleWithSAML"
	| "CreateFederationProvider"
	| "UpdateFederationProvider"
	| "DeleteFederationProvider"
	| "SetTags"
	| "RemoveTags"
	| "Authorize"
	| "Denied"
	| "UpdateAccountSettings";

export type AuditEventSource = "iam" | "sts" | "federation";

export type AuditResponseStatus = "success" | "denied" | "error";

export type FederationProviderType = "oidc" | "saml" | "web-identity";

export type PolicyValidationSeverity = "ERROR" | "WARNING" | "SUGGESTION";

export type SimulationDecision = "ALLOWED" | "DENIED" | "IMPLICIT_DENY";

export interface AuthorizationRequest {
	principal: string;
	principalType: PrincipalType;
	action: string;
	resource: string;
	context: Record<string, unknown>;
	sessionTags?: Record<string, string>;
	requestTags?: Record<string, string>;
}

export interface AuthorizationDecision {
	decision: SimulationDecision;
	matchedStatements: PolicyStatement[];
	evaluationPath: string[];
}

export interface AuditEvent {
	id: string;
	eventTime: Date;
	eventType: AuditEventType | string;
	eventSource: AuditEventSource;
	principalId: string;
	principalType: PrincipalType | string;
	action: string;
	resource: string;
	sourceIp: string;
	userAgent: string;
	requestParams: Record<string, unknown>;
	responseStatus: AuditResponseStatus;
	errorCode?: string;
	sessionId?: string;
	mfaAuthenticated: boolean;
}

export interface CredentialReportEntry {
	userId: string;
	userName: string;
	userPath: string;
	userCreatedAt: Date;
	passwordLastUsed: Date | null;
	passwordLastChanged: Date | null;
	mfaActive: boolean;
	accessKey1Id: string | null;
	accessKey1Status: AccessKeyStatus | null;
	accessKey1LastUsed: Date | null;
	accessKey1LastRotated: Date | null;
	accessKey2Id: string | null;
	accessKey2Status: AccessKeyStatus | null;
	accessKey2LastUsed: Date | null;
	accessKey2LastRotated: Date | null;
}

export interface PasswordPolicy {
	minLength: number;
	requireUppercase: boolean;
	requireLowercase: boolean;
	requireNumbers: boolean;
	requireSymbols: boolean;
	maxAgeDays: number | null;
	preventReuseCount: number;
}

export interface ClaimMappingRule {
	source: string;
	target: string;
	transform?: string;
}

export interface PolicyValidationFinding {
	severity: PolicyValidationSeverity;
	message: string;
	statementIndex?: number;
	field?: string;
}

export interface AccessAnalyzerFinding {
	severity: PolicyValidationSeverity;
	findingType: "public-access" | "cross-account" | "overly-permissive";
	resource: string;
	principal: string;
	action: string;
	condition?: string;
	recommendation: string;
}

export interface UnusedAccessFinding {
	principalId: string;
	principalType: string;
	permission: string;
	grantedVia: string;
	lastUsed: Date | null;
	daysSinceUsed: number | null;
}

export interface TemporaryCredentials {
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken: string;
	expiration: Date;
}

export interface STSCallerIdentity {
	userId: string;
	account: string;
	arn: string;
	principalType: PrincipalType;
	assumedRoleId?: string;
}

export interface IamQuotas {
	maxUsersPerAccount: number;
	maxGroupsPerAccount: number;
	maxRolesPerAccount: number;
	maxPoliciesPerAccount: number;
	maxPolicyVersions: number;
	maxAccessKeysPerUser: number;
	maxGroupsPerUser: number;
	maxPoliciesPerEntity: number;
	maxInlinePoliciesPerEntity: number;
	maxTagsPerResource: number;
}

export interface IamOptions {
	accountId?: string;
	partition?: string;
	enforceOnAllRoutes?: boolean;
	rootUserId?: string;
	actionMapping?: Record<string, string>;
	quotas?: Partial<IamQuotas>;
	sts?: {
		defaultDuration?: number;
		maxDuration?: number;
		cleanupInterval?: number;
	};
	federation?: {
		oidc?: { enabled: boolean };
		saml?: { enabled: boolean };
		webIdentity?: { enabled: boolean };
	};
	mfa?: {
		protectedActions?: string[];
		maxAge?: number;
	};
	audit?: {
		enabled?: boolean;
		retentionDays?: number;
		onEvent?: (event: AuditEvent) => void | Promise<void>;
		redactedFields?: string[];
	};
	passwordPolicy?: Partial<PasswordPolicy>;
	schema?: Record<
		string,
		{
			modelName?: string;
			fields?: Record<string, { fieldName?: string }>;
		}
	>;
	hooks?: {
		beforeCreatePolicy?: (data: unknown) => Promise<{ data?: unknown } | void>;
		afterCreatePolicy?: (policy: unknown) => Promise<void>;
		beforeAssumeRole?: (data: unknown) => Promise<{ data?: unknown } | void>;
		afterAssumeRole?: (session: unknown) => Promise<void>;
		beforeAuthorize?: (
			request: AuthorizationRequest,
		) => Promise<{ decision?: "ALLOW" | "DENY" } | void>;
		afterAuthorize?: (
			request: AuthorizationRequest,
			decision: AuthorizationDecision,
		) => Promise<void>;
	};
}
