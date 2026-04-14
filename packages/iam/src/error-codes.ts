import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const IAM_ERROR_CODES = defineErrorCodes({
	POLICY_NOT_FOUND: "The specified policy was not found",
	POLICY_ALREADY_EXISTS: "A policy with this name already exists",
	POLICY_VERSION_NOT_FOUND: "The specified policy version was not found",
	POLICY_VERSION_LIMIT_EXCEEDED:
		"Maximum number of policy versions has been reached",
	POLICY_DOCUMENT_INVALID: "The policy document is not valid JSON",
	POLICY_DOCUMENT_MALFORMED:
		"The policy document does not meet the requirements",
	POLICY_IN_USE:
		"The policy cannot be deleted because it is attached to entities",
	POLICY_ATTACHMENT_LIMIT_EXCEEDED:
		"Maximum number of policy attachments for this entity has been reached",
	POLICY_NOT_ATTACHABLE: "This policy type cannot be attached to entities",
	POLICY_ALREADY_ATTACHED:
		"This policy is already attached to the specified entity",
	POLICY_NOT_ATTACHED: "This policy is not attached to the specified entity",
	INLINE_POLICY_LIMIT_EXCEEDED:
		"Maximum number of inline policies for this entity has been reached",
	SERVICE_LINKED_POLICY_PROTECTED:
		"Service-linked policies cannot be modified or deleted",

	USER_NOT_FOUND: "The specified IAM user was not found",
	USER_ALREADY_EXISTS: "An IAM user with this name already exists",
	USER_LIMIT_EXCEEDED: "Maximum number of IAM users has been reached",
	USER_HAS_DEPENDENCIES:
		"Cannot delete user with active access keys or group memberships",

	GROUP_NOT_FOUND: "The specified IAM group was not found",
	GROUP_ALREADY_EXISTS: "An IAM group with this name already exists",
	GROUP_LIMIT_EXCEEDED: "Maximum number of IAM groups has been reached",
	GROUP_MEMBERSHIP_LIMIT_EXCEEDED:
		"Maximum number of groups per user has been reached",
	USER_NOT_IN_GROUP: "The specified user is not a member of this group",
	USER_ALREADY_IN_GROUP: "The specified user is already a member of this group",

	ROLE_NOT_FOUND: "The specified IAM role was not found",
	ROLE_ALREADY_EXISTS: "An IAM role with this name already exists",
	ROLE_LIMIT_EXCEEDED: "Maximum number of IAM roles has been reached",
	ROLE_IN_USE: "The role cannot be deleted because it is currently assumed",
	SERVICE_LINKED_ROLE_PROTECTED:
		"Service-linked roles cannot be modified or deleted",
	TRUST_POLICY_INVALID: "The trust policy document is not valid",

	ACCESS_KEY_NOT_FOUND: "The specified access key was not found",
	ACCESS_KEY_LIMIT_EXCEEDED:
		"Maximum number of access keys per user has been reached",
	ACCESS_KEY_ALREADY_INACTIVE: "The access key is already inactive",
	ACCESS_KEY_ALREADY_ACTIVE: "The access key is already active",

	SERVICE_ACCOUNT_NOT_FOUND: "The specified service account was not found",
	SERVICE_ACCOUNT_ALREADY_EXISTS:
		"A service account with this name already exists",

	STS_TOKEN_EXPIRED: "The temporary security credentials have expired",
	STS_TOKEN_INVALID: "The temporary security credentials are not valid",
	STS_SESSION_POLICY_TOO_LARGE: "The session policy exceeds the size limit",
	STS_DURATION_EXCEEDED:
		"The requested duration exceeds the maximum allowed for this role",
	STS_CHAINED_ROLE_DURATION_EXCEEDED:
		"Chained role assumption cannot exceed the remaining session duration",

	ASSUME_ROLE_DENIED:
		"The trust policy does not allow this principal to assume the role",
	ASSUME_ROLE_MFA_REQUIRED:
		"MFA authentication is required to assume this role",
	ASSUME_ROLE_EXTERNAL_ID_REQUIRED:
		"An external ID is required by the trust policy but was not provided",
	ASSUME_ROLE_SOURCE_IDENTITY_MISMATCH:
		"Source identity cannot be changed during chained role assumption",

	FEDERATION_PROVIDER_NOT_FOUND:
		"The specified federation provider was not found",
	FEDERATION_PROVIDER_ALREADY_EXISTS:
		"A federation provider with this name already exists",
	FEDERATION_TOKEN_INVALID: "The token from the identity provider is not valid",
	FEDERATION_TOKEN_EXPIRED: "The token from the identity provider has expired",
	FEDERATION_AUDIENCE_MISMATCH:
		"The token audience does not match the expected audience",
	FEDERATION_ISSUER_MISMATCH:
		"The token issuer does not match the registered provider",
	FEDERATION_THUMBPRINT_MISMATCH:
		"The certificate thumbprint does not match the registered thumbprint",
	FEDERATION_DISCOVERY_FAILED: "Failed to fetch the OIDC discovery document",
	FEDERATION_SAML_INVALID: "The SAML assertion is not valid",

	TAG_LIMIT_EXCEEDED: "Maximum number of tags per resource has been reached",
	TAG_KEY_INVALID: "Tag key must be between 1 and 128 characters",
	TAG_VALUE_INVALID: "Tag value must be between 0 and 256 characters",

	MFA_REQUIRED: "Multi-factor authentication is required for this operation",
	MFA_NOT_CONFIGURED:
		"MFA is not configured for this user but is required by policy",

	AUTHORIZATION_DENIED: "Access denied by IAM policy",
	AUTHORIZATION_IMPLICIT_DENY:
		"No matching allow statement found in any policy",
	AUTHORIZATION_EXPLICIT_DENY: "An explicit deny statement matched the request",
	AUTHORIZATION_BOUNDARY_DENY:
		"The permission boundary does not allow this action",
	AUTHORIZATION_SESSION_POLICY_DENY:
		"The session policy does not allow this action",

	INVALID_ARN: "The specified ARN is not valid",
	INVALID_ACTION: "The specified action format is not valid",
	INVALID_CONDITION_OPERATOR:
		"The specified condition operator is not recognized",
	INVALID_CONDITION_VALUE:
		"The condition value is not valid for the specified operator",

	ACCOUNT_SETTINGS_NOT_FOUND: "Account settings have not been configured",
	ACCOUNT_ALIAS_ALREADY_EXISTS: "This account alias is already in use",

	QUOTA_EXCEEDED: "A resource quota has been exceeded",
	INVALID_INPUT: "The request input is not valid",
	INTERNAL_ERROR: "An internal error occurred",

	SIGNING_INVALID: "The request signature is not valid",
	SIGNING_EXPIRED: "The request signature has expired",
	SIGNING_MISSING_HEADERS: "Required signed headers are missing",
});
