import { describe, expect, it } from "vitest";
import type { MFAEnforcementConfig } from "../mfa/enforcement";
import { checkMFARequired } from "../mfa/enforcement";

const config: MFAEnforcementConfig = {
	protectedActions: ["iam:DeleteUser", "iam:CreateRole", "iam:Assume*"],
	maxAge: 3600,
};

describe("checkMFARequired", () => {
	it("should not require MFA for unprotected actions", () => {
		const result = checkMFARequired("iam:GetUser", config, {
			twoFactorEnabled: false,
		});
		expect(result.required).toBe(false);
	});

	it("should require MFA for exact-match protected actions", () => {
		const result = checkMFARequired("iam:DeleteUser", config, {
			twoFactorEnabled: true,
			mfaVerifiedAt: null,
		});
		expect(result.required).toBe(true);
		expect(result.error).toContain("Multi-factor authentication");
	});

	it("should require MFA for wildcard-match protected actions", () => {
		const result = checkMFARequired("iam:AssumeRole", config, {
			twoFactorEnabled: true,
			mfaVerifiedAt: null,
		});
		expect(result.required).toBe(true);
	});

	it("should pass when MFA verified recently", () => {
		const result = checkMFARequired("iam:DeleteUser", config, {
			twoFactorEnabled: true,
			mfaVerifiedAt: new Date(),
		});
		expect(result.required).toBe(false);
	});

	it("should require MFA when verification is stale", () => {
		const staleTime = new Date(Date.now() - 7200 * 1000);
		const result = checkMFARequired("iam:DeleteUser", config, {
			twoFactorEnabled: true,
			mfaVerifiedAt: staleTime,
		});
		expect(result.required).toBe(true);
	});

	it("should error when MFA not configured but required", () => {
		const result = checkMFARequired("iam:DeleteUser", config, {
			twoFactorEnabled: false,
			mfaVerifiedAt: null,
		});
		expect(result.required).toBe(true);
		expect(result.error).toContain("not configured");
	});

	it("should pass with no maxAge when MFA is verified", () => {
		const noMaxAgeConfig: MFAEnforcementConfig = {
			protectedActions: ["iam:DeleteUser"],
		};
		const result = checkMFARequired("iam:DeleteUser", noMaxAgeConfig, {
			twoFactorEnabled: true,
			mfaVerifiedAt: new Date(Date.now() - 999999 * 1000),
		});
		expect(result.required).toBe(false);
	});
});
