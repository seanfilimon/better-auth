import { describe, expect, it } from "vitest";
import {
	createPolicySet,
	evaluate,
	isAllowed,
	isDenied,
} from "../policy/engine";
import type { AuthorizationRequest, PolicyDocument } from "../types";

function makeRequest(
	overrides: Partial<AuthorizationRequest> = {},
): AuthorizationRequest {
	return {
		principal: "arn:auth:iam::123:user/jane",
		principalType: "User",
		action: "iam:GetUser",
		resource: "arn:auth:iam::123:user/jane",
		context: {},
		...overrides,
	};
}

describe("policy engine - root user bypass", () => {
	it("should allow everything for root user", () => {
		const decision = evaluate(makeRequest(), createPolicySet({}), {
			isRootUser: true,
			variableContext: {},
		});
		expect(isAllowed(decision)).toBe(true);
		expect(decision.evaluationPath).toContain("Root user bypass: ALLOW");
	});
});

describe("policy engine - explicit deny", () => {
	it("should deny when explicit deny matches", () => {
		const denyPolicy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [
				{
					Effect: "Deny",
					Action: "iam:*",
					Resource: "*",
				},
			],
		};
		const allowPolicy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [
				{
					Effect: "Allow",
					Action: "iam:*",
					Resource: "*",
				},
			],
		};

		const decision = evaluate(
			makeRequest(),
			createPolicySet({
				identityPolicies: [allowPolicy],
				resourcePolicies: [denyPolicy],
			}),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isDenied(decision)).toBe(true);
		expect(decision.decision).toBe("DENIED");
	});
});

describe("policy engine - identity allow", () => {
	it("should allow when identity policy allows", () => {
		const allowPolicy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [
				{
					Effect: "Allow",
					Action: "iam:GetUser",
					Resource: "arn:auth:iam::123:user/*",
				},
			],
		};

		const decision = evaluate(
			makeRequest(),
			createPolicySet({ identityPolicies: [allowPolicy] }),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isAllowed(decision)).toBe(true);
	});

	it("should implicit deny when no policy matches", () => {
		const decision = evaluate(makeRequest(), createPolicySet({}), {
			isRootUser: false,
			variableContext: {},
		});
		expect(decision.decision).toBe("IMPLICIT_DENY");
	});
});

describe("policy engine - permission boundary", () => {
	it("should deny when boundary does not include the action", () => {
		const allowPolicy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [
				{
					Effect: "Allow",
					Action: "*",
					Resource: "*",
				},
			],
		};
		const boundary: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [
				{
					Effect: "Allow",
					Action: "s3:*",
					Resource: "*",
				},
			],
		};

		const decision = evaluate(
			makeRequest({ action: "iam:CreateUser" }),
			createPolicySet({
				identityPolicies: [allowPolicy],
				permissionBoundaries: [boundary],
			}),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isDenied(decision)).toBe(true);
	});

	it("should allow when boundary includes the action", () => {
		const allowPolicy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [{ Effect: "Allow", Action: "iam:*", Resource: "*" }],
		};
		const boundary: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [{ Effect: "Allow", Action: "iam:*", Resource: "*" }],
		};

		const decision = evaluate(
			makeRequest(),
			createPolicySet({
				identityPolicies: [allowPolicy],
				permissionBoundaries: [boundary],
			}),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isAllowed(decision)).toBe(true);
	});
});

describe("policy engine - session policy", () => {
	it("should deny when session policy does not allow", () => {
		const allowPolicy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }],
		};
		const sessionPolicy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }],
		};

		const decision = evaluate(
			makeRequest({ action: "iam:CreateUser" }),
			createPolicySet({
				identityPolicies: [allowPolicy],
				sessionPolicies: [sessionPolicy],
			}),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isDenied(decision)).toBe(true);
	});
});

describe("policy engine - resource policy", () => {
	it("should allow via resource policy even without identity policy", () => {
		const resourcePolicy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [
				{
					Effect: "Allow",
					Action: "iam:GetUser",
					Resource: "*",
					Principal: "*",
				},
			],
		};

		const decision = evaluate(
			makeRequest(),
			createPolicySet({ resourcePolicies: [resourcePolicy] }),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isAllowed(decision)).toBe(true);
	});
});

describe("policy engine - NotAction", () => {
	it("should allow everything except the listed actions", () => {
		const policy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [
				{
					Effect: "Allow",
					NotAction: "iam:DeleteUser",
					Resource: "*",
				},
			],
		};

		const allowDecision = evaluate(
			makeRequest({ action: "iam:GetUser" }),
			createPolicySet({ identityPolicies: [policy] }),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isAllowed(allowDecision)).toBe(true);

		const denyDecision = evaluate(
			makeRequest({ action: "iam:DeleteUser" }),
			createPolicySet({ identityPolicies: [policy] }),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isDenied(denyDecision)).toBe(true);
	});
});

describe("policy engine - conditions", () => {
	it("should evaluate conditions on Allow statements", () => {
		const policy: PolicyDocument = {
			Version: "2024-01-01",
			Statement: [
				{
					Effect: "Allow",
					Action: "*",
					Resource: "*",
					Condition: {
						Bool: { "iam:MultiFactorAuthPresent": "true" },
					},
				},
			],
		};

		const allowDecision = evaluate(
			makeRequest({ context: { "iam:MultiFactorAuthPresent": "true" } }),
			createPolicySet({ identityPolicies: [policy] }),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isAllowed(allowDecision)).toBe(true);

		const denyDecision = evaluate(
			makeRequest({ context: { "iam:MultiFactorAuthPresent": "false" } }),
			createPolicySet({ identityPolicies: [policy] }),
			{ isRootUser: false, variableContext: {} },
		);
		expect(isDenied(denyDecision)).toBe(true);
	});
});
