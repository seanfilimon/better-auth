import { describe, expect, it } from "vitest";
import { evaluateConditionBlock } from "../policy/conditions";

describe("String operators", () => {
	it("StringEquals should match exact strings", () => {
		expect(
			evaluateConditionBlock(
				{ StringEquals: { "iam:PrincipalType": "User" } },
				{ "iam:PrincipalType": "User" },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ StringEquals: { "iam:PrincipalType": "User" } },
				{ "iam:PrincipalType": "Role" },
			),
		).toBe(false);
	});

	it("StringNotEquals should not match", () => {
		expect(
			evaluateConditionBlock(
				{ StringNotEquals: { "iam:PrincipalType": "User" } },
				{ "iam:PrincipalType": "Role" },
			),
		).toBe(true);
	});

	it("StringEqualsIgnoreCase should match case-insensitively", () => {
		expect(
			evaluateConditionBlock(
				{ StringEqualsIgnoreCase: { env: "Production" } },
				{ env: "production" },
			),
		).toBe(true);
	});

	it("StringLike should support glob patterns", () => {
		expect(
			evaluateConditionBlock(
				{ StringLike: { path: "/engineering/*" } },
				{ path: "/engineering/team-a" },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ StringLike: { path: "/engineering/*" } },
				{ path: "/sales/team-b" },
			),
		).toBe(false);
	});

	it("StringNotLike should negate glob", () => {
		expect(
			evaluateConditionBlock(
				{ StringNotLike: { path: "/admin/*" } },
				{ path: "/engineering/team" },
			),
		).toBe(true);
	});
});

describe("Numeric operators", () => {
	it("NumericEquals should compare numbers", () => {
		expect(
			evaluateConditionBlock({ NumericEquals: { age: "30" } }, { age: 30 }),
		).toBe(true);
	});

	it("NumericLessThan should work", () => {
		expect(
			evaluateConditionBlock(
				{ NumericLessThan: { "iam:MultiFactorAuthAge": "3600" } },
				{ "iam:MultiFactorAuthAge": 1800 },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ NumericLessThan: { "iam:MultiFactorAuthAge": "3600" } },
				{ "iam:MultiFactorAuthAge": 7200 },
			),
		).toBe(false);
	});

	it("NumericGreaterThanEquals should work", () => {
		expect(
			evaluateConditionBlock(
				{ NumericGreaterThanEquals: { count: "5" } },
				{ count: 5 },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ NumericGreaterThanEquals: { count: "5" } },
				{ count: 4 },
			),
		).toBe(false);
	});
});

describe("Date operators", () => {
	it("DateLessThan should compare dates", () => {
		const future = new Date(Date.now() + 86400000).toISOString();
		expect(
			evaluateConditionBlock(
				{ DateLessThan: { "iam:CurrentTime": future } },
				{ "iam:CurrentTime": new Date().toISOString() },
			),
		).toBe(true);
	});

	it("DateGreaterThan should compare dates", () => {
		const past = new Date(Date.now() - 86400000).toISOString();
		expect(
			evaluateConditionBlock(
				{ DateGreaterThan: { "iam:CurrentTime": past } },
				{ "iam:CurrentTime": new Date().toISOString() },
			),
		).toBe(true);
	});
});

describe("Bool operator", () => {
	it("should match boolean strings", () => {
		expect(
			evaluateConditionBlock(
				{ Bool: { "iam:MultiFactorAuthPresent": "true" } },
				{ "iam:MultiFactorAuthPresent": "true" },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ Bool: { "iam:MultiFactorAuthPresent": "true" } },
				{ "iam:MultiFactorAuthPresent": "false" },
			),
		).toBe(false);
	});
});

describe("IP Address operators", () => {
	it("IpAddress should match CIDR ranges", () => {
		expect(
			evaluateConditionBlock(
				{ IpAddress: { "iam:SourceIp": "192.168.1.0/24" } },
				{ "iam:SourceIp": "192.168.1.100" },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ IpAddress: { "iam:SourceIp": "192.168.1.0/24" } },
				{ "iam:SourceIp": "10.0.0.1" },
			),
		).toBe(false);
	});

	it("NotIpAddress should negate CIDR match", () => {
		expect(
			evaluateConditionBlock(
				{ NotIpAddress: { "iam:SourceIp": "10.0.0.0/8" } },
				{ "iam:SourceIp": "192.168.1.1" },
			),
		).toBe(true);
	});
});

describe("ARN operators", () => {
	it("ArnLike should match ARN patterns", () => {
		expect(
			evaluateConditionBlock(
				{ ArnLike: { resource: "arn:auth:iam::123:user/*" } },
				{ resource: "arn:auth:iam::123:user/jane" },
			),
		).toBe(true);
	});

	it("ArnNotLike should negate", () => {
		expect(
			evaluateConditionBlock(
				{ ArnNotLike: { resource: "arn:auth:iam::123:role/*" } },
				{ resource: "arn:auth:iam::123:user/jane" },
			),
		).toBe(true);
	});
});

describe("Null operator", () => {
	it("should check for null/undefined keys", () => {
		expect(
			evaluateConditionBlock(
				{ Null: { "iam:PrincipalTag/department": "true" } },
				{},
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ Null: { "iam:PrincipalTag/department": "false" } },
				{ "iam:PrincipalTag/department": "engineering" },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ Null: { "iam:PrincipalTag/department": "true" } },
				{ "iam:PrincipalTag/department": "engineering" },
			),
		).toBe(false);
	});
});

describe("IfExists modifier", () => {
	it("should pass if key is missing", () => {
		expect(
			evaluateConditionBlock(
				{ StringEqualsIfExists: { "iam:PrincipalTag/env": "prod" } },
				{},
			),
		).toBe(true);
	});

	it("should evaluate if key exists", () => {
		expect(
			evaluateConditionBlock(
				{ StringEqualsIfExists: { "iam:PrincipalTag/env": "prod" } },
				{ "iam:PrincipalTag/env": "prod" },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ StringEqualsIfExists: { "iam:PrincipalTag/env": "prod" } },
				{ "iam:PrincipalTag/env": "dev" },
			),
		).toBe(false);
	});
});

describe("ForAllValues / ForAnyValue modifiers", () => {
	it("ForAllValues should require all values match", () => {
		expect(
			evaluateConditionBlock(
				{ "ForAllValues:StringEquals": { tags: ["a", "b"] } },
				{ tags: ["a", "b"] },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ "ForAllValues:StringEquals": { tags: ["a", "b"] } },
				{ tags: ["a", "c"] },
			),
		).toBe(false);
	});

	it("ForAnyValue should require at least one match", () => {
		expect(
			evaluateConditionBlock(
				{ "ForAnyValue:StringEquals": { tags: ["a", "b"] } },
				{ tags: ["c", "b"] },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{ "ForAnyValue:StringEquals": { tags: ["a", "b"] } },
				{ tags: ["c", "d"] },
			),
		).toBe(false);
	});
});

describe("multiple conditions (AND logic)", () => {
	it("should require all condition operators to be true", () => {
		expect(
			evaluateConditionBlock(
				{
					StringEquals: { env: "prod" },
					Bool: { "iam:MultiFactorAuthPresent": "true" },
				},
				{ env: "prod", "iam:MultiFactorAuthPresent": "true" },
			),
		).toBe(true);
		expect(
			evaluateConditionBlock(
				{
					StringEquals: { env: "prod" },
					Bool: { "iam:MultiFactorAuthPresent": "true" },
				},
				{ env: "prod", "iam:MultiFactorAuthPresent": "false" },
			),
		).toBe(false);
	});
});

describe("missing context key (non-IfExists)", () => {
	it("should return false when required key is missing", () => {
		expect(
			evaluateConditionBlock(
				{ StringEquals: { "iam:PrincipalType": "User" } },
				{},
			),
		).toBe(false);
	});
});
