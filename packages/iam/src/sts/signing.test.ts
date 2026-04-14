import { describe, expect, it } from "vitest";
import {
	createCanonicalRequest,
	parseAuthorizationHeader,
	signRequest,
	verifyRequestSignature,
} from "../sts/signing";

const SECRET_KEY = "test-secret-key-for-signing";
const ACCESS_KEY_ID = "AKIATEST123";

describe("createCanonicalRequest", () => {
	it("should produce a deterministic canonical string", async () => {
		const canonical = await createCanonicalRequest({
			method: "GET",
			path: "/api/iam/users",
			headers: { host: "localhost:3000", "content-type": "application/json" },
			signedHeaders: ["host", "content-type"],
			body: "",
		});
		expect(canonical).toContain("GET");
		expect(canonical).toContain("/api/iam/users");
		expect(canonical).toContain("content-type:application/json");
		expect(canonical).toContain("host:localhost:3000");
	});

	it("should sort query parameters", async () => {
		const canonical = await createCanonicalRequest({
			method: "GET",
			path: "/test",
			query: { z: "last", a: "first" },
			headers: { host: "localhost" },
			signedHeaders: ["host"],
		});
		expect(canonical).toContain("a=first&z=last");
	});

	it("should sort signed headers", async () => {
		const canonical = await createCanonicalRequest({
			method: "POST",
			path: "/test",
			headers: { host: "localhost", "x-custom": "value", accept: "text/html" },
			signedHeaders: ["x-custom", "accept", "host"],
		});
		const lines = canonical.split("\n");
		const headerLines = lines.slice(3, 6);
		expect(headerLines[0]).toBe("accept:text/html");
		expect(headerLines[1]).toBe("host:localhost");
		expect(headerLines[2]).toBe("x-custom:value");
	});
});

describe("signRequest", () => {
	it("should produce a valid authorization header", async () => {
		const timestamp = new Date().toISOString();
		const authHeader = await signRequest({
			method: "GET",
			path: "/api/iam/users",
			headers: { host: "localhost:3000" },
			body: "",
			secretKey: SECRET_KEY,
			accessKeyId: ACCESS_KEY_ID,
			signedHeaders: ["host"],
			timestamp,
		});
		expect(authHeader).toContain("IAM-HMAC");
		expect(authHeader).toContain(`Credential=${ACCESS_KEY_ID}`);
		expect(authHeader).toContain("SignedHeaders=host");
		expect(authHeader).toContain("Signature=");
	});

	it("should produce different signatures for different bodies", async () => {
		const timestamp = new Date().toISOString();
		const sig1 = await signRequest({
			method: "POST",
			path: "/test",
			headers: { host: "localhost" },
			body: '{"action":"create"}',
			secretKey: SECRET_KEY,
			accessKeyId: ACCESS_KEY_ID,
			signedHeaders: ["host"],
			timestamp,
		});
		const sig2 = await signRequest({
			method: "POST",
			path: "/test",
			headers: { host: "localhost" },
			body: '{"action":"delete"}',
			secretKey: SECRET_KEY,
			accessKeyId: ACCESS_KEY_ID,
			signedHeaders: ["host"],
			timestamp,
		});
		expect(sig1).not.toBe(sig2);
	});
});

describe("parseAuthorizationHeader", () => {
	it("should parse a valid authorization header", () => {
		const header =
			"IAM-HMAC Credential=AKIATEST123,SignedHeaders=host;content-type,Signature=abc123def";
		const result = parseAuthorizationHeader(header);
		expect(result).not.toBeNull();
		expect(result!.accessKeyId).toBe("AKIATEST123");
		expect(result!.signedHeaders).toEqual(["host", "content-type"]);
		expect(result!.signature).toBe("abc123def");
	});

	it("should return null for non-matching prefix", () => {
		expect(parseAuthorizationHeader("Bearer abc123")).toBeNull();
	});

	it("should return null for malformed header", () => {
		expect(parseAuthorizationHeader("AUTH-HMAC-SHA256 garbage")).toBeNull();
	});
});

describe("verifyRequestSignature", () => {
	it("should verify a valid signature", async () => {
		const timestamp = new Date().toISOString();
		const params = {
			method: "GET",
			path: "/api/iam/users",
			headers: { host: "localhost:3000" },
			body: "",
			signedHeaders: ["host"],
			timestamp,
		};

		const authHeader = await signRequest({
			...params,
			secretKey: SECRET_KEY,
			accessKeyId: ACCESS_KEY_ID,
		});

		const parsed = parseAuthorizationHeader(authHeader);
		expect(parsed).not.toBeNull();

		const isValid = await verifyRequestSignature({
			...params,
			secretKey: SECRET_KEY,
			signedHeaders: parsed!.signedHeaders,
			providedSignature: parsed!.signature,
		});
		expect(isValid).toBe(true);
	});

	it("should reject a tampered signature", async () => {
		const timestamp = new Date().toISOString();
		const isValid = await verifyRequestSignature({
			method: "GET",
			path: "/api/iam/users",
			headers: { host: "localhost:3000" },
			body: "",
			secretKey: SECRET_KEY,
			signedHeaders: ["host"],
			providedSignature:
				"0000000000000000000000000000000000000000000000000000000000000000",
			timestamp,
		});
		expect(isValid).toBe(false);
	});

	it("should reject when body is tampered", async () => {
		const timestamp = new Date().toISOString();
		const params = {
			method: "POST",
			path: "/api/test",
			headers: { host: "localhost" },
			signedHeaders: ["host"],
			timestamp,
		};

		const authHeader = await signRequest({
			...params,
			body: '{"original":true}',
			secretKey: SECRET_KEY,
			accessKeyId: ACCESS_KEY_ID,
		});

		const parsed = parseAuthorizationHeader(authHeader);
		const isValid = await verifyRequestSignature({
			...params,
			body: '{"tampered":true}',
			secretKey: SECRET_KEY,
			signedHeaders: parsed!.signedHeaders,
			providedSignature: parsed!.signature,
		});
		expect(isValid).toBe(false);
	});
});
