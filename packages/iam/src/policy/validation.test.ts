import { describe, expect, it } from "vitest";
import { validatePolicyDocument } from "../policy/validation";

describe("policy validation - structure", () => {
	it("should reject non-object input", () => {
		const findings = validatePolicyDocument("not an object");
		expect(findings.some((f) => f.severity === "ERROR")).toBe(true);
	});

	it("should reject missing Version", () => {
		const findings = validatePolicyDocument({
			Statement: [{ Effect: "Allow", Action: "*" }],
		});
		expect(findings.some((f) => f.field === "Version")).toBe(true);
	});

	it("should reject missing Statement", () => {
		const findings = validatePolicyDocument({ Version: "2024-01-01" });
		expect(findings.some((f) => f.field === "Statement")).toBe(true);
	});

	it("should reject empty Statement array", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [],
		});
		expect(findings.some((f) => f.severity === "ERROR")).toBe(true);
	});

	it("should accept valid policy", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [{ Effect: "Allow", Action: "iam:GetUser", Resource: "*" }],
		});
		const errors = findings.filter((f) => f.severity === "ERROR");
		expect(errors).toHaveLength(0);
	});
});

describe("policy validation - statements", () => {
	it("should reject invalid Effect", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [{ Effect: "Maybe", Action: "*" }],
		});
		expect(findings.some((f) => f.field === "Effect")).toBe(true);
	});

	it("should reject missing Action and NotAction", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [{ Effect: "Allow", Resource: "*" }],
		});
		expect(findings.some((f) => f.severity === "ERROR")).toBe(true);
	});

	it("should reject both Action and NotAction", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [{ Effect: "Allow", Action: "*", NotAction: "iam:*" }],
		});
		expect(findings.some((f) => f.severity === "ERROR")).toBe(true);
	});

	it("should reject both Resource and NotResource", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [
				{ Effect: "Allow", Action: "*", Resource: "*", NotResource: "*" },
			],
		});
		expect(findings.some((f) => f.severity === "ERROR")).toBe(true);
	});
});

describe("policy validation - security warnings", () => {
	it("should warn on wildcard Action + Resource", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }],
		});
		expect(findings.some((f) => f.severity === "WARNING")).toBe(true);
	});

	it("should warn on NotAction with Allow", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [
				{ Effect: "Allow", NotAction: "iam:DeleteUser", Resource: "*" },
			],
		});
		expect(
			findings.some(
				(f) => f.severity === "WARNING" && f.message.includes("NotAction"),
			),
		).toBe(true);
	});

	it("should warn on Principal: *", () => {
		const findings = validatePolicyDocument({
			Version: "2024-01-01",
			Statement: [
				{ Effect: "Allow", Action: "*", Resource: "*", Principal: "*" },
			],
		});
		expect(findings.some((f) => f.message.includes("Principal"))).toBe(true);
	});
});
