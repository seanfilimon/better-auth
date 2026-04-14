import type { BetterAuthClientPlugin } from "better-auth/client";
import { IAM_ERROR_CODES } from "./error-codes";
import type { iam } from "./index";
import { PACKAGE_VERSION } from "./version";

export const iamClient = () => {
	return {
		id: "iam-client",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof iam>,
		pathMethods: {
			"/iam/policy/get": "GET",
			"/iam/policy/list": "GET",
			"/iam/policy/list-versions": "GET",
			"/iam/policy/list-attachments": "GET",
			"/iam/user/get": "GET",
			"/iam/user/list": "GET",
			"/iam/user/list-policies": "GET",
			"/iam/group/get": "GET",
			"/iam/group/list": "GET",
			"/iam/role/get": "GET",
			"/iam/role/list": "GET",
			"/iam/access-key/list": "GET",
			"/iam/access-key/get-last-used": "GET",
			"/iam/service-account/get": "GET",
			"/iam/service-account/list": "GET",
			"/iam/sts/get-caller-identity": "GET",
			"/iam/federation/get-provider": "GET",
			"/iam/federation/list-providers": "GET",
			"/iam/tag/list": "GET",
			"/iam/audit/query": "GET",
			"/iam/audit/credential-report": "GET",
			"/iam/audit/access-report": "GET",
			"/iam/analysis/access": "GET",
			"/iam/analysis/unused-access": "GET",
			"/iam/account/get-settings": "GET",
		},
		$ERROR_CODES: IAM_ERROR_CODES,
	} satisfies BetterAuthClientPlugin;
};

export * from "./error-codes";
