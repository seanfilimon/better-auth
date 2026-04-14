import { describe, expect, it } from "vitest";
import {
	buildVariableContext,
	resolveTagContextKeys,
	substituteInStringOrArray,
	substituteVariables,
} from "../policy/variables";

describe("substituteVariables", () => {
	it("should replace ${iam:username} with principalName", () => {
		const result = substituteVariables(
			"arn:auth:iam::123:user/${iam:username}",
			{ principalName: "jane" },
		);
		expect(result).toBe("arn:auth:iam::123:user/jane");
	});

	it("should replace principal tag variables", () => {
		const result = substituteVariables("${iam:PrincipalTag/department}", {
			principalTags: { department: "engineering" },
		});
		expect(result).toBe("engineering");
	});

	it("should return empty string for unresolved variables", () => {
		const result = substituteVariables("prefix-${iam:unknownvar}-suffix", {});
		expect(result).toBe("prefix--suffix");
	});

	it("should handle strings with no variables", () => {
		const result = substituteVariables("plain-string", {
			principalName: "jane",
		});
		expect(result).toBe("plain-string");
	});

	it("should handle multiple variables", () => {
		const result = substituteVariables("${iam:username}/${iam:userid}", {
			principalName: "jane",
			principalId: "uid-123",
		});
		expect(result).toBe("jane/uid-123");
	});
});

describe("substituteInStringOrArray", () => {
	it("should substitute in a single string", () => {
		const result = substituteInStringOrArray(
			"arn:auth:iam::123:user/${iam:username}",
			{ principalName: "jane" },
		);
		expect(result).toBe("arn:auth:iam::123:user/jane");
	});

	it("should substitute in each element of an array", () => {
		const result = substituteInStringOrArray(["${iam:username}", "literal"], {
			principalName: "jane",
		});
		expect(result).toEqual(["jane", "literal"]);
	});
});

describe("buildVariableContext", () => {
	it("should build a context object with all fields", () => {
		const ctx = buildVariableContext({
			principalId: "uid-123",
			principalName: "jane",
			principalType: "User",
			sourceIp: "192.168.1.1",
			orgId: "org-1",
		});
		expect(ctx.principalId).toBe("uid-123");
		expect(ctx.principalName).toBe("jane");
		expect(ctx.principalType).toBe("User");
		expect(ctx.sourceIp).toBe("192.168.1.1");
		expect(ctx.orgId).toBe("org-1");
		expect(ctx.currentTime).toBeDefined();
		expect(ctx.epochTime).toBeDefined();
	});

	it("should default optional fields to empty strings", () => {
		const ctx = buildVariableContext({
			principalId: "uid-123",
			principalName: "jane",
			principalType: "User",
		});
		expect(ctx.sourceIdentity).toBe("");
		expect(ctx.sourceIp).toBe("");
		expect(ctx.userAgent).toBe("");
	});
});

describe("resolveTagContextKeys", () => {
	it("should prefix principal tags correctly", () => {
		const keys = resolveTagContextKeys({
			principalTags: { department: "engineering", team: "platform" },
		});
		expect(keys["iam:PrincipalTag/department"]).toBe("engineering");
		expect(keys["iam:PrincipalTag/team"]).toBe("platform");
	});

	it("should prefix resource tags correctly", () => {
		const keys = resolveTagContextKeys({
			resourceTags: { env: "production" },
		});
		expect(keys["iam:ResourceTag/env"]).toBe("production");
	});

	it("should prefix request tags correctly", () => {
		const keys = resolveTagContextKeys({
			requestTags: { project: "alpha" },
		});
		expect(keys["iam:RequestTag/project"]).toBe("alpha");
	});

	it("should handle empty params", () => {
		const keys = resolveTagContextKeys({});
		expect(Object.keys(keys)).toHaveLength(0);
	});
});
