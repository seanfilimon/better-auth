import { describe, expect, it } from "vitest";
import {
	buildARN,
	buildIamARN,
	globMatch,
	matchAction,
	matchActionList,
	matchARN,
	matchResourceList,
	parseARN,
} from "../policy/arn";

describe("ARN parsing", () => {
	it("should parse a valid ARN", () => {
		const result = parseARN("arn:auth:iam::123456:user/engineering/jane");
		expect(result).not.toBeNull();
		expect(result!.partition).toBe("auth");
		expect(result!.service).toBe("iam");
		expect(result!.region).toBe("");
		expect(result!.account).toBe("123456");
		expect(result!.resourceType).toBe("user");
		expect(result!.resourcePath).toBe("engineering/jane");
	});

	it("should parse ARN with region", () => {
		const result = parseARN("arn:auth:s3:us-east-1:123:bucket/my-bucket");
		expect(result).not.toBeNull();
		expect(result!.region).toBe("us-east-1");
		expect(result!.resourceType).toBe("bucket");
		expect(result!.resourcePath).toBe("my-bucket");
	});

	it("should return null for invalid ARN", () => {
		expect(parseARN("not-an-arn")).toBeNull();
		expect(parseARN("arn:only:two")).toBeNull();
		expect(parseARN("")).toBeNull();
	});

	it("should parse ARN with no resource path", () => {
		const result = parseARN("arn:auth:iam::123:root");
		expect(result).not.toBeNull();
		expect(result!.resourceType).toBe("root");
		expect(result!.resourcePath).toBe("");
	});
});

describe("ARN building", () => {
	it("should build a valid ARN", () => {
		const arn = buildARN("auth", "iam", "", "123456", "user", "jane");
		expect(arn).toBe("arn:auth:iam::123456:user/jane");
	});

	it("should build ARN with no resource path", () => {
		const arn = buildARN("auth", "iam", "", "123456", "root", "");
		expect(arn).toBe("arn:auth:iam::123456:root");
	});

	it("buildIamARN should produce correct IAM ARN", () => {
		const arn = buildIamARN("auth", "123456", "user", "engineering/jane");
		expect(arn).toBe("arn:auth:iam::123456:user/engineering/jane");
	});
});

describe("ARN matching", () => {
	it("should match identical ARNs", () => {
		expect(
			matchARN("arn:auth:iam::123:user/jane", "arn:auth:iam::123:user/jane"),
		).toBe(true);
	});

	it("should match wildcard pattern *", () => {
		expect(matchARN("*", "arn:auth:iam::123:user/jane")).toBe(true);
	});

	it("should match resource wildcard", () => {
		expect(
			matchARN("arn:auth:iam::123:user/*", "arn:auth:iam::123:user/jane"),
		).toBe(true);
	});

	it("should match path-based wildcard", () => {
		expect(
			matchARN(
				"arn:auth:iam::123:user/engineering/*",
				"arn:auth:iam::123:user/engineering/jane",
			),
		).toBe(true);
	});

	it("should not match different accounts", () => {
		expect(
			matchARN("arn:auth:iam::123:user/*", "arn:auth:iam::456:user/jane"),
		).toBe(false);
	});

	it("should match service wildcard", () => {
		expect(matchARN("arn:auth:*::123:*", "arn:auth:iam::123:user/jane")).toBe(
			true,
		);
	});

	it("should not match different resource types", () => {
		expect(
			matchARN("arn:auth:iam::123:role/*", "arn:auth:iam::123:user/jane"),
		).toBe(false);
	});
});

describe("glob matching", () => {
	it("should match exact strings", () => {
		expect(globMatch("hello", "hello")).toBe(true);
	});

	it("should match wildcard *", () => {
		expect(globMatch("*", "anything")).toBe(true);
		expect(globMatch("hello*", "helloworld")).toBe(true);
		expect(globMatch("*world", "helloworld")).toBe(true);
		expect(globMatch("he*ld", "helloworld")).toBe(true);
	});

	it("should match question mark ?", () => {
		expect(globMatch("h?llo", "hello")).toBe(true);
		expect(globMatch("h?llo", "hallo")).toBe(true);
		expect(globMatch("h?llo", "hxllo")).toBe(true);
	});

	it("should not match when different", () => {
		expect(globMatch("hello", "world")).toBe(false);
		expect(globMatch("h?llo", "heello")).toBe(false);
	});
});

describe("action matching", () => {
	it("should match exact actions case-insensitively", () => {
		expect(matchAction("iam:CreateUser", "iam:CreateUser")).toBe(true);
		expect(matchAction("iam:CreateUser", "iam:createuser")).toBe(true);
	});

	it("should match wildcard actions", () => {
		expect(matchAction("iam:*", "iam:CreateUser")).toBe(true);
		expect(matchAction("*", "iam:CreateUser")).toBe(true);
	});

	it("should not match different services", () => {
		expect(matchAction("s3:*", "iam:CreateUser")).toBe(false);
	});

	it("matchActionList should match any in list", () => {
		expect(
			matchActionList(["iam:CreateUser", "iam:DeleteUser"], "iam:DeleteUser"),
		).toBe(true);
		expect(
			matchActionList(["iam:CreateUser", "iam:DeleteUser"], "iam:GetUser"),
		).toBe(false);
	});

	it("matchResourceList should match any in list", () => {
		expect(
			matchResourceList(
				["arn:auth:iam::123:user/jane", "arn:auth:iam::123:user/bob"],
				"arn:auth:iam::123:user/bob",
			),
		).toBe(true);
	});
});
