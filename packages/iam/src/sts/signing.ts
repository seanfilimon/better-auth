import { SIGNING_ALGORITHM, SIGNING_HEADER_PREFIX } from "../constants";
import { constantTimeEqual } from "../utils/crypto";

interface SigningParams {
	method: string;
	path: string;
	query?: Record<string, string>;
	headers: Record<string, string>;
	body?: string;
	secretKey: string;
	accessKeyId: string;
	signedHeaders: string[];
	timestamp: string;
}

async function hmacSign(
	key: ArrayBuffer | string,
	data: string,
): Promise<ArrayBuffer> {
	const keyData = typeof key === "string" ? new TextEncoder().encode(key) : key;
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		keyData,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

async function sha256(data: string): Promise<string> {
	const hash = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(data),
	);
	return Array.from(new Uint8Array(hash))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function bufferToHex(buffer: ArrayBuffer): string {
	return Array.from(new Uint8Array(buffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function createCanonicalRequest(params: {
	method: string;
	path: string;
	query?: Record<string, string>;
	headers: Record<string, string>;
	signedHeaders: string[];
	body?: string;
}): Promise<string> {
	const sortedQuery = params.query
		? Object.entries(params.query)
				.sort(([a], [b]) => a.localeCompare(b))
				.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
				.join("&")
		: "";

	const sortedHeaders = params.signedHeaders.map((h) => h.toLowerCase()).sort();

	const canonicalHeaders = sortedHeaders
		.map((h) => `${h}:${(params.headers[h] || "").trim()}`)
		.join("\n");

	const signedHeadersStr = sortedHeaders.join(";");
	const bodyHash = await sha256(params.body ?? "");

	return [
		params.method.toUpperCase(),
		params.path,
		sortedQuery,
		canonicalHeaders,
		"",
		signedHeadersStr,
		bodyHash,
	].join("\n");
}

export async function signRequest(params: SigningParams): Promise<string> {
	const canonical = await createCanonicalRequest({
		method: params.method,
		path: params.path,
		query: params.query,
		headers: params.headers,
		signedHeaders: params.signedHeaders,
		body: params.body,
	});

	const stringToSign = [
		SIGNING_ALGORITHM,
		params.timestamp,
		await sha256(canonical),
	].join("\n");

	const sigBytes = await hmacSign(params.secretKey, stringToSign);
	const signature = bufferToHex(sigBytes);

	const signedHeadersStr = params.signedHeaders
		.map((h) => h.toLowerCase())
		.sort()
		.join(";");

	return `${SIGNING_HEADER_PREFIX} Credential=${params.accessKeyId},SignedHeaders=${signedHeadersStr},Signature=${signature}`;
}

export function parseAuthorizationHeader(header: string): {
	accessKeyId: string;
	signedHeaders: string[];
	signature: string;
} | null {
	if (!header.startsWith(SIGNING_HEADER_PREFIX + " ")) return null;

	const parts = header.substring(SIGNING_HEADER_PREFIX.length + 1).split(",");
	const parsed: Record<string, string> = {};

	for (const part of parts) {
		const eqIdx = part.indexOf("=");
		if (eqIdx < 0) continue;
		parsed[part.substring(0, eqIdx).trim()] = part.substring(eqIdx + 1).trim();
	}

	if (!parsed.Credential || !parsed.SignedHeaders || !parsed.Signature) {
		return null;
	}

	return {
		accessKeyId: parsed.Credential,
		signedHeaders: parsed.SignedHeaders.split(";"),
		signature: parsed.Signature,
	};
}

export async function verifyRequestSignature(params: {
	method: string;
	path: string;
	query?: Record<string, string>;
	headers: Record<string, string>;
	body?: string;
	secretKey: string;
	signedHeaders: string[];
	providedSignature: string;
	timestamp: string;
}): Promise<boolean> {
	const canonical = await createCanonicalRequest({
		method: params.method,
		path: params.path,
		query: params.query,
		headers: params.headers,
		signedHeaders: params.signedHeaders,
		body: params.body,
	});

	const stringToSign = [
		SIGNING_ALGORITHM,
		params.timestamp,
		await sha256(canonical),
	].join("\n");

	const sigBytes = await hmacSign(params.secretKey, stringToSign);
	const expected = bufferToHex(sigBytes);
	return constantTimeEqual(expected, params.providedSignature);
}
