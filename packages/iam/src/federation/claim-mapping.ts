import type { ClaimMappingRule } from "../types";

export function applyClaimMapping(
	rules: ClaimMappingRule[],
	claims: Record<string, unknown>,
): Record<string, string> {
	const result: Record<string, string> = {};

	for (const rule of rules) {
		const sourceValue = claims[rule.source];
		if (sourceValue === undefined || sourceValue === null) continue;

		let value = String(sourceValue);

		if (rule.transform) {
			value = applyTransform(value, rule.transform);
		}

		if (rule.target.startsWith("tag:")) {
			result[rule.target.substring(4)] = value;
		} else {
			result[rule.target] = value;
		}
	}

	return result;
}

function applyTransform(value: string, transform: string): string {
	if (transform.startsWith("split(") && transform.endsWith(")")) {
		const inner = transform.substring(6, transform.length - 1);
		const bracketMatch = inner.match(/^(.+)\)\[(\d+)\]$/);
		if (bracketMatch) {
			const delimiter = bracketMatch[1]!;
			const index = parseInt(bracketMatch[2]!, 10);
			const parts = value.split(delimiter);
			return parts[index] ?? value;
		}
		const parts = value.split(inner);
		return parts[parts.length - 1] ?? value;
	}

	if (transform === "lowercase") return value.toLowerCase();
	if (transform === "uppercase") return value.toUpperCase();
	if (transform === "trim") return value.trim();

	if (transform.startsWith("replace(") && transform.endsWith(")")) {
		const inner = transform.substring(8, transform.length - 1);
		const commaIdx = inner.indexOf(",");
		if (commaIdx >= 0) {
			const from = inner.substring(0, commaIdx);
			const to = inner.substring(commaIdx + 1);
			return value.split(from).join(to);
		}
	}

	if (transform.startsWith("prefix(") && transform.endsWith(")")) {
		return transform.substring(7, transform.length - 1) + value;
	}

	if (transform.startsWith("suffix(") && transform.endsWith(")")) {
		return value + transform.substring(7, transform.length - 1);
	}

	return value;
}

export function validateClaimMappingRules(rules: unknown): {
	valid: boolean;
	errors: string[];
} {
	const errors: string[] = [];

	if (!Array.isArray(rules)) {
		return { valid: false, errors: ["Claim mapping rules must be an array"] };
	}

	for (let i = 0; i < rules.length; i++) {
		const rule = rules[i];
		if (!rule || typeof rule !== "object") {
			errors.push(`Rule at index ${i} must be an object`);
			continue;
		}
		if (typeof (rule as any).source !== "string") {
			errors.push(`Rule at index ${i} must have a "source" string`);
		}
		if (typeof (rule as any).target !== "string") {
			errors.push(`Rule at index ${i} must have a "target" string`);
		}
	}

	return { valid: errors.length === 0, errors };
}
