import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";

interface OIDCDiscoveryDocument {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint?: string;
	jwks_uri: string;
	id_token_signing_alg_values_supported?: string[];
	[key: string]: unknown;
}

export async function fetchOIDCDiscovery(
	providerUrl: string,
): Promise<OIDCDiscoveryDocument> {
	if (!providerUrl.startsWith("https://")) {
		throw new Error("OIDC provider URL must use HTTPS");
	}

	const url = new URL(providerUrl);
	const hostname = url.hostname;
	if (
		hostname === "localhost" ||
		hostname === "127.0.0.1" ||
		hostname === "0.0.0.0" ||
		hostname.startsWith("10.") ||
		hostname.startsWith("192.168.") ||
		hostname.startsWith("172.") ||
		hostname === "[::1]"
	) {
		throw new Error(
			"OIDC provider URL must not point to private/internal addresses",
		);
	}

	const wellKnown = providerUrl.endsWith("/")
		? `${providerUrl}.well-known/openid-configuration`
		: `${providerUrl}/.well-known/openid-configuration`;

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), 10_000);
	try {
		const response = await fetch(wellKnown, { signal: controller.signal });
		if (!response.ok) {
			throw new Error(IAM_ERROR_CODES.FEDERATION_DISCOVERY_FAILED.message);
		}
		return response.json() as Promise<OIDCDiscoveryDocument>;
	} finally {
		clearTimeout(timeoutId);
	}
}

export async function validateOIDCToken(
	token: string,
	provider: {
		providerUrl: string;
		clientId?: string;
		audiences?: string[];
		metadataDocument?: OIDCDiscoveryDocument;
	},
): Promise<{
	valid: boolean;
	claims?: Record<string, unknown>;
	error?: string;
}> {
	try {
		const parts = token.split(".");
		if (parts.length !== 3) {
			return { valid: false, error: "Invalid JWT format" };
		}

		const headerStr = atob(parts[0]!.replace(/-/g, "+").replace(/_/g, "/"));
		const header = JSON.parse(headerStr) as Record<string, unknown>;

		const payloadStr = atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/"));
		const claims = JSON.parse(payloadStr) as Record<string, unknown>;

		if (header.alg === "none") {
			return { valid: false, error: "Unsigned JWT (alg=none) is not accepted" };
		}

		const discovery =
			provider.metadataDocument ??
			(await fetchOIDCDiscovery(provider.providerUrl));

		const jwksValid = await verifyJwtWithJwks(
			token,
			discovery.jwks_uri,
			header,
		);
		if (!jwksValid) {
			return {
				valid: false,
				error: "JWT signature verification failed",
			};
		}

		if (claims.iss !== discovery.issuer) {
			return {
				valid: false,
				error: IAM_ERROR_CODES.FEDERATION_ISSUER_MISMATCH.message,
			};
		}

		const nowSeconds = Math.floor(Date.now() / 1000);

		if (!claims.exp || typeof claims.exp !== "number") {
			return {
				valid: false,
				error: "JWT missing required 'exp' claim",
			};
		}
		if (nowSeconds > claims.exp) {
			return {
				valid: false,
				error: IAM_ERROR_CODES.FEDERATION_TOKEN_EXPIRED.message,
			};
		}

		if (claims.nbf && typeof claims.nbf === "number") {
			if (nowSeconds < claims.nbf - CLOCK_SKEW_SECONDS) {
				return {
					valid: false,
					error: "JWT is not yet valid (nbf claim is in the future)",
				};
			}
		}

		if (claims.iat && typeof claims.iat === "number") {
			if (nowSeconds < claims.iat - CLOCK_SKEW_SECONDS) {
				return {
					valid: false,
					error: "JWT issued-at (iat) is in the future",
				};
			}
		}

		const audiences =
			provider.audiences ?? (provider.clientId ? [provider.clientId] : []);
		if (audiences.length > 0) {
			if (!claims.aud) {
				return {
					valid: false,
					error: IAM_ERROR_CODES.FEDERATION_AUDIENCE_MISMATCH.message,
				};
			}
			const tokenAud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
			const hasMatch = tokenAud.some((a: unknown) =>
				audiences.includes(String(a)),
			);
			if (!hasMatch) {
				return {
					valid: false,
					error: IAM_ERROR_CODES.FEDERATION_AUDIENCE_MISMATCH.message,
				};
			}
		}

		return { valid: true, claims };
	} catch (_e) {
		return {
			valid: false,
			error: IAM_ERROR_CODES.FEDERATION_TOKEN_INVALID.message,
		};
	}
}

const CLOCK_SKEW_SECONDS = 60;
const OIDC_FETCH_TIMEOUT_MS = 10_000;

async function fetchJwks(jwksUri: string): Promise<JsonWebKeySet> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), OIDC_FETCH_TIMEOUT_MS);
	try {
		const response = await fetch(jwksUri, { signal: controller.signal });
		if (!response.ok) {
			throw new Error(`JWKS fetch failed: ${response.status}`);
		}
		return response.json() as Promise<JsonWebKeySet>;
	} finally {
		clearTimeout(timeoutId);
	}
}

interface JsonWebKeySet {
	keys: JsonWebKey[];
}

interface JsonWebKey {
	kid?: string;
	kty: string;
	alg?: string;
	use?: string;
	n?: string;
	e?: string;
	[key: string]: unknown;
}

function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
	const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
	const padding = "=".repeat((4 - (base64.length % 4)) % 4);
	const binary = atob(base64 + padding);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer;
}

function getAlgorithmParams(
	alg: string,
): { name: string; hash: string } | null {
	const mapping: Record<string, { name: string; hash: string }> = {
		RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
		RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
	};
	return mapping[alg] ?? null;
}

async function verifyJwtWithJwks(
	token: string,
	jwksUri: string,
	header: Record<string, unknown>,
): Promise<boolean> {
	try {
		const alg = String(header.alg ?? "RS256");
		const algParams = getAlgorithmParams(alg);
		if (!algParams) return false;

		const jwks = await fetchJwks(jwksUri);
		const kid = header.kid ? String(header.kid) : undefined;

		const matchingKeys = kid
			? jwks.keys.filter((k) => k.kid === kid)
			: jwks.keys.filter(
					(k) => (!k.use || k.use === "sig") && (!k.alg || k.alg === alg),
				);

		if (matchingKeys.length === 0) return false;

		const parts = token.split(".");
		const signedData = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
		const signature = base64UrlToArrayBuffer(parts[2]!);

		for (const jwk of matchingKeys) {
			try {
				const cryptoKey = await crypto.subtle.importKey(
					"jwk",
					jwk as globalThis.JsonWebKey,
					{ name: algParams.name, hash: algParams.hash },
					false,
					["verify"],
				);
				const valid = await crypto.subtle.verify(
					algParams.name,
					cryptoKey,
					signature,
					signedData,
				);
				if (valid) return true;
			} catch {
				continue;
			}
		}

		return false;
	} catch {
		return false;
	}
}

export async function createOIDCProvider(
	iamAdapter: IamAdapter,
	data: {
		id: string;
		name: string;
		providerUrl: string;
		clientId?: string;
		clientSecret?: string;
		audiences?: string[];
		thumbprints?: string[];
	},
) {
	const existing = await iamAdapter.findFederationProviderByName(data.name);
	if (existing) {
		throw new Error(IAM_ERROR_CODES.FEDERATION_PROVIDER_ALREADY_EXISTS.message);
	}

	let metadataDocument: OIDCDiscoveryDocument | undefined;
	try {
		metadataDocument = await fetchOIDCDiscovery(data.providerUrl);
	} catch {
		// Metadata fetch is best-effort during creation
	}

	return iamAdapter.createFederationProvider({
		id: data.id,
		name: data.name,
		type: "oidc",
		providerUrl: data.providerUrl,
		clientId: data.clientId,
		clientSecret: data.clientSecret,
		metadataDocument,
		audiences: data.audiences,
		thumbprints: data.thumbprints,
	});
}
