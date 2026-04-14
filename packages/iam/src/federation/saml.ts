import type { IamAdapter } from "../adapter";
import { IAM_ERROR_CODES } from "../error-codes";

interface SAMLAssertion {
	issuer: string;
	subject: string;
	subjectNameId: string;
	conditions?: {
		notBefore?: string;
		notOnOrAfter?: string;
		audience?: string;
	};
	attributes: Record<string, string | string[]>;
	rawXml: string;
	signaturePresent: boolean;
}

export function parseSAMLResponse(samlResponse: string): SAMLAssertion | null {
	try {
		if (!samlResponse || samlResponse.length > 1_000_000) {
			return null;
		}

		const decoded = atob(samlResponse);

		if (decoded.includes("<!DOCTYPE") || decoded.includes("<!ENTITY")) {
			return null;
		}

		const issuerMatch = decoded.match(
			/<(?:saml2?:)?Issuer[^>]*>([^<]+)<\/(?:saml2?:)?Issuer>/,
		);
		const subjectMatch = decoded.match(
			/<(?:saml2?:)?NameID[^>]*>([^<]+)<\/(?:saml2?:)?NameID>/,
		);

		if (!issuerMatch || !subjectMatch) {
			return null;
		}

		const attributes: Record<string, string | string[]> = {};
		const attrRegex =
			/<(?:saml2?:)?Attribute\s+Name="([^"]+)"[^>]*>([\s\S]*?)<\/(?:saml2?:)?Attribute>/g;
		let match: RegExpExecArray | null;
		while ((match = attrRegex.exec(decoded)) !== null) {
			const name = match[1]!;
			const valueRegex =
				/<(?:saml2?:)?AttributeValue[^>]*>([^<]*)<\/(?:saml2?:)?AttributeValue>/g;
			const values: string[] = [];
			let valMatch: RegExpExecArray | null;
			while ((valMatch = valueRegex.exec(match[2]!)) !== null) {
				values.push(valMatch[1]!);
			}
			attributes[name] = values.length === 1 ? values[0]! : values;
		}

		let conditions: SAMLAssertion["conditions"];
		const condMatch = decoded.match(/<(?:saml2?:)?Conditions\s+([^>]+)>/);
		if (condMatch) {
			const notBefore = condMatch[1]?.match(/NotBefore="([^"]+)"/)?.[1];
			const notOnOrAfter = condMatch[1]?.match(/NotOnOrAfter="([^"]+)"/)?.[1];
			const audMatch = decoded.match(
				/<(?:saml2?:)?Audience>([^<]+)<\/(?:saml2?:)?Audience>/,
			);
			conditions = {
				notBefore,
				notOnOrAfter,
				audience: audMatch?.[1],
			};
		}

		const hasSignature =
			decoded.includes("<ds:Signature") || decoded.includes("<Signature");

		return {
			issuer: issuerMatch[1]!,
			subject: subjectMatch[1]!,
			subjectNameId: subjectMatch[1]!,
			conditions,
			attributes,
			rawXml: decoded,
			signaturePresent: hasSignature,
		};
	} catch {
		return null;
	}
}

export function validateSAMLAssertion(
	assertion: SAMLAssertion,
	provider: { providerUrl: string; audiences?: string[] },
): { valid: boolean; error?: string } {
	if (!assertion.signaturePresent) {
		return {
			valid: false,
			error: "SAML assertion is unsigned. Signature is required for security.",
		};
	}

	if (assertion.issuer !== provider.providerUrl) {
		return {
			valid: false,
			error: IAM_ERROR_CODES.FEDERATION_ISSUER_MISMATCH.message,
		};
	}

	if (assertion.conditions?.notOnOrAfter) {
		const expiry = new Date(assertion.conditions.notOnOrAfter);
		if (expiry < new Date()) {
			return {
				valid: false,
				error: IAM_ERROR_CODES.FEDERATION_TOKEN_EXPIRED.message,
			};
		}
	}

	if (assertion.conditions?.notBefore) {
		const notBefore = new Date(assertion.conditions.notBefore);
		if (notBefore > new Date()) {
			return {
				valid: false,
				error: IAM_ERROR_CODES.FEDERATION_SAML_INVALID.message,
			};
		}
	}

	const audiences = provider.audiences
		? typeof provider.audiences === "string"
			? JSON.parse(provider.audiences as string)
			: provider.audiences
		: [];
	if (audiences.length > 0 && assertion.conditions?.audience) {
		if (!audiences.includes(assertion.conditions.audience)) {
			return {
				valid: false,
				error: IAM_ERROR_CODES.FEDERATION_AUDIENCE_MISMATCH.message,
			};
		}
	}

	return { valid: true };
}

export async function createSAMLProvider(
	iamAdapter: IamAdapter,
	data: {
		id: string;
		name: string;
		providerUrl: string;
		metadataDocument?: unknown;
		audiences?: string[];
	},
) {
	const existing = await iamAdapter.findFederationProviderByName(data.name);
	if (existing) {
		throw new Error(IAM_ERROR_CODES.FEDERATION_PROVIDER_ALREADY_EXISTS.message);
	}

	return iamAdapter.createFederationProvider({
		id: data.id,
		name: data.name,
		type: "saml",
		providerUrl: data.providerUrl,
		metadataDocument: data.metadataDocument,
		audiences: data.audiences,
	});
}
