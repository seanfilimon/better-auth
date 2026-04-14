import { describe, expect, it } from "vitest";
import { parseSAMLResponse, validateSAMLAssertion } from "../federation/saml";

function buildSAMLXml(opts: {
	issuer: string;
	nameId: string;
	notBefore?: string;
	notOnOrAfter?: string;
	audience?: string;
	attributes?: Record<string, string>;
}) {
	let attrBlock = "";
	if (opts.attributes) {
		for (const [name, val] of Object.entries(opts.attributes)) {
			attrBlock += `<saml:Attribute Name="${name}"><saml:AttributeValue>${val}</saml:AttributeValue></saml:Attribute>`;
		}
	}

	let conditions = "";
	if (opts.notBefore || opts.notOnOrAfter || opts.audience) {
		let condAttrs = "";
		if (opts.notBefore) condAttrs += ` NotBefore="${opts.notBefore}"`;
		if (opts.notOnOrAfter) condAttrs += ` NotOnOrAfter="${opts.notOnOrAfter}"`;
		conditions = `<saml:Conditions${condAttrs}>`;
		if (opts.audience) {
			conditions += `<saml:Audience>${opts.audience}</saml:Audience>`;
		}
		conditions += `</saml:Conditions>`;
	}

	return `<samlp:Response><saml:Assertion><saml:Issuer>${opts.issuer}</saml:Issuer><saml:Subject><saml:NameID>${opts.nameId}</saml:NameID></saml:Subject>${conditions}<saml:AttributeStatement>${attrBlock}</saml:AttributeStatement></saml:Assertion></samlp:Response>`;
}

describe("parseSAMLResponse", () => {
	it("should parse a valid SAML response", () => {
		const xml = buildSAMLXml({
			issuer: "https://idp.example.com",
			nameId: "user@example.com",
			attributes: { email: "user@example.com", role: "admin" },
		});
		const encoded = btoa(xml);
		const result = parseSAMLResponse(encoded);

		expect(result).not.toBeNull();
		expect(result!.issuer).toBe("https://idp.example.com");
		expect(result!.subject).toBe("user@example.com");
		expect(result!.subjectNameId).toBe("user@example.com");
		expect(result!.attributes.email).toBe("user@example.com");
		expect(result!.attributes.role).toBe("admin");
	});

	it("should parse conditions", () => {
		const xml = buildSAMLXml({
			issuer: "https://idp.example.com",
			nameId: "user@example.com",
			notBefore: "2024-01-01T00:00:00Z",
			notOnOrAfter: "2099-01-01T00:00:00Z",
			audience: "urn:my:app",
		});
		const encoded = btoa(xml);
		const result = parseSAMLResponse(encoded);

		expect(result).not.toBeNull();
		expect(result!.conditions?.notBefore).toBe("2024-01-01T00:00:00Z");
		expect(result!.conditions?.notOnOrAfter).toBe("2099-01-01T00:00:00Z");
		expect(result!.conditions?.audience).toBe("urn:my:app");
	});

	it("should return null for invalid base64", () => {
		expect(parseSAMLResponse("!!!not-valid-base64!!!")).toBeNull();
	});

	it("should return null when missing issuer", () => {
		const xml = `<samlp:Response><saml:Subject><saml:NameID>user@test.com</saml:NameID></saml:Subject></samlp:Response>`;
		expect(parseSAMLResponse(btoa(xml))).toBeNull();
	});
});

describe("validateSAMLAssertion", () => {
	it("should pass for valid assertion", () => {
		const assertion = {
			issuer: "https://idp.example.com",
			subject: "user@example.com",
			subjectNameId: "user@example.com",
			attributes: {},
			rawXml: "",
			signaturePresent: true,
		};
		const result = validateSAMLAssertion(assertion, {
			providerUrl: "https://idp.example.com",
		});
		expect(result.valid).toBe(true);
	});

	it("should fail for unsigned assertion", () => {
		const assertion = {
			issuer: "https://idp.example.com",
			subject: "user@example.com",
			subjectNameId: "user@example.com",
			attributes: {},
			rawXml: "",
			signaturePresent: false,
		};
		const result = validateSAMLAssertion(assertion, {
			providerUrl: "https://idp.example.com",
		});
		expect(result.valid).toBe(false);
		expect(result.error).toContain("unsigned");
	});

	it("should fail for mismatched issuer", () => {
		const assertion = {
			issuer: "https://other-idp.com",
			subject: "user@example.com",
			subjectNameId: "user@example.com",
			attributes: {},
			rawXml: "",
			signaturePresent: true,
		};
		const result = validateSAMLAssertion(assertion, {
			providerUrl: "https://idp.example.com",
		});
		expect(result.valid).toBe(false);
		expect(result.error).toContain("issuer");
	});

	it("should fail for expired assertion", () => {
		const assertion = {
			issuer: "https://idp.example.com",
			subject: "user@example.com",
			subjectNameId: "user@example.com",
			conditions: {
				notOnOrAfter: "2020-01-01T00:00:00Z",
			},
			attributes: {},
			rawXml: "",
			signaturePresent: true,
		};
		const result = validateSAMLAssertion(assertion, {
			providerUrl: "https://idp.example.com",
		});
		expect(result.valid).toBe(false);
		expect(result.error).toContain("expired");
	});

	it("should fail for audience mismatch", () => {
		const assertion = {
			issuer: "https://idp.example.com",
			subject: "user@example.com",
			subjectNameId: "user@example.com",
			conditions: {
				notOnOrAfter: "2099-01-01T00:00:00Z",
				audience: "urn:wrong:app",
			},
			attributes: {},
			rawXml: "",
			signaturePresent: true,
		};
		const result = validateSAMLAssertion(assertion, {
			providerUrl: "https://idp.example.com",
			audiences: ["urn:my:app"],
		});
		expect(result.valid).toBe(false);
		expect(result.error).toContain("audience");
	});
});
