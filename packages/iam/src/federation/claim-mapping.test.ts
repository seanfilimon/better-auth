import { describe, expect, it } from "vitest";
import {
	applyClaimMapping,
	validateClaimMappingRules,
} from "../federation/claim-mapping";
import type { ClaimMappingRule } from "../types";

describe("applyClaimMapping", () => {
	it("should map simple claims", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "email", target: "username" },
			{ source: "name", target: "displayName" },
		];
		const claims = { email: "jane@example.com", name: "Jane Doe" };
		const result = applyClaimMapping(rules, claims);
		expect(result.username).toBe("jane@example.com");
		expect(result.displayName).toBe("Jane Doe");
	});

	it("should skip missing claims", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "email", target: "username" },
			{ source: "phone", target: "phone" },
		];
		const claims = { email: "jane@example.com" };
		const result = applyClaimMapping(rules, claims);
		expect(result.username).toBe("jane@example.com");
		expect(result.phone).toBeUndefined();
	});

	it("should apply lowercase transform", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "name", target: "lower_name", transform: "lowercase" },
		];
		const result = applyClaimMapping(rules, { name: "Jane DOE" });
		expect(result.lower_name).toBe("jane doe");
	});

	it("should apply uppercase transform", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "code", target: "code_upper", transform: "uppercase" },
		];
		const result = applyClaimMapping(rules, { code: "abc" });
		expect(result.code_upper).toBe("ABC");
	});

	it("should apply trim transform", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "val", target: "trimmed", transform: "trim" },
		];
		const result = applyClaimMapping(rules, { val: "  hello  " });
		expect(result.trimmed).toBe("hello");
	});

	it("should apply prefix transform", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "val", target: "prefixed", transform: "prefix(org-)" },
		];
		const result = applyClaimMapping(rules, { val: "team-a" });
		expect(result.prefixed).toBe("org-team-a");
	});

	it("should apply suffix transform", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "val", target: "suffixed", transform: "suffix(-dept)" },
		];
		const result = applyClaimMapping(rules, { val: "engineering" });
		expect(result.suffixed).toBe("engineering-dept");
	});

	it("should apply replace transform", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "val", target: "replaced", transform: "replace(@,-at-)" },
		];
		const result = applyClaimMapping(rules, { val: "user@host" });
		expect(result.replaced).toBe("user-at-host");
	});

	it("should apply split transform", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "email", target: "domain", transform: "split(@)" },
		];
		const result = applyClaimMapping(rules, { email: "jane@example.com" });
		expect(result.domain).toBe("example.com");
	});

	it("should handle tag: prefix in target", () => {
		const rules: ClaimMappingRule[] = [
			{ source: "department", target: "tag:department" },
		];
		const result = applyClaimMapping(rules, { department: "engineering" });
		expect(result.department).toBe("engineering");
	});
});

describe("validateClaimMappingRules", () => {
	it("should accept valid rules", () => {
		const result = validateClaimMappingRules([
			{ source: "email", target: "username" },
		]);
		expect(result.valid).toBe(true);
		expect(result.errors).toHaveLength(0);
	});

	it("should reject non-array", () => {
		const result = validateClaimMappingRules("not an array");
		expect(result.valid).toBe(false);
	});

	it("should reject rules without source", () => {
		const result = validateClaimMappingRules([{ target: "username" }]);
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("source");
	});

	it("should reject rules without target", () => {
		const result = validateClaimMappingRules([{ source: "email" }]);
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("target");
	});
});
