import {
	ARN_PREFIX,
	ARN_QUESTION_MARK,
	ARN_SEPARATOR,
	ARN_WILDCARD,
	DEFAULT_PARTITION,
} from "../constants";
import type { ParsedARN } from "../types";

export function parseARN(arn: string): ParsedARN | null {
	if (!arn.startsWith(ARN_PREFIX + ARN_SEPARATOR)) return null;
	const parts = arn.split(ARN_SEPARATOR);
	if (parts.length < 6) return null;

	const resourceParts = parts.slice(5).join(ARN_SEPARATOR);
	const slashIndex = resourceParts.indexOf("/");

	return {
		partition: parts[1] || DEFAULT_PARTITION,
		service: parts[2] || "",
		region: parts[3] || "",
		account: parts[4] || "",
		resourceType:
			slashIndex >= 0 ? resourceParts.substring(0, slashIndex) : resourceParts,
		resourcePath:
			slashIndex >= 0 ? resourceParts.substring(slashIndex + 1) : "",
	};
}

export function buildARN(
	partition: string,
	service: string,
	region: string,
	account: string,
	resourceType: string,
	resourcePath: string,
): string {
	const resource = resourcePath
		? `${resourceType}/${resourcePath}`
		: resourceType;
	return [ARN_PREFIX, partition, service, region, account, resource].join(
		ARN_SEPARATOR,
	);
}

export function matchARN(pattern: string, target: string): boolean {
	if (pattern === ARN_WILDCARD) return true;
	if (pattern === target) return true;

	const patternParsed = parseARN(pattern);
	const targetParsed = parseARN(target);

	if (!patternParsed || !targetParsed) {
		return globMatch(pattern, target);
	}

	return (
		matchComponent(patternParsed.partition, targetParsed.partition) &&
		matchComponent(patternParsed.service, targetParsed.service) &&
		matchComponent(patternParsed.region, targetParsed.region) &&
		matchComponent(patternParsed.account, targetParsed.account) &&
		matchComponent(patternParsed.resourceType, targetParsed.resourceType) &&
		matchResourcePath(patternParsed.resourcePath, targetParsed.resourcePath)
	);
}

function matchComponent(pattern: string, target: string): boolean {
	if (pattern === ARN_WILDCARD || pattern === "") return true;
	return pattern === target;
}

function matchResourcePath(pattern: string, target: string): boolean {
	if (pattern === ARN_WILDCARD || pattern === "") return true;
	if (pattern === target) return true;
	return globMatch(pattern, target);
}

export function globMatch(pattern: string, text: string): boolean {
	if (pattern === ARN_WILDCARD) return true;
	if (pattern === text) return true;

	let pi = 0;
	let ti = 0;
	let starPI = -1;
	let starTI = -1;

	while (ti < text.length) {
		const pc = pattern[pi];
		const tc = text[ti];

		if (pc === ARN_WILDCARD) {
			starPI = pi;
			starTI = ti;
			pi++;
		} else if (pc === ARN_QUESTION_MARK || pc === tc) {
			pi++;
			ti++;
		} else if (starPI >= 0) {
			pi = starPI + 1;
			starTI++;
			ti = starTI;
		} else {
			return false;
		}
	}

	while (pi < pattern.length && pattern[pi] === ARN_WILDCARD) {
		pi++;
	}

	return pi === pattern.length;
}

export function matchAction(pattern: string, action: string): boolean {
	if (pattern === ARN_WILDCARD) return true;
	return globMatch(pattern.toLowerCase(), action.toLowerCase());
}

export function matchActionList(
	patterns: string | string[],
	action: string,
): boolean {
	const list = Array.isArray(patterns) ? patterns : [patterns];
	return list.some((p) => matchAction(p, action));
}

export function matchResourceList(
	patterns: string | string[],
	resource: string,
): boolean {
	const list = Array.isArray(patterns) ? patterns : [patterns];
	return list.some((p) => matchARN(p, resource));
}

export function buildIamARN(
	partition: string,
	account: string,
	resourceType: string,
	resourcePath: string,
): string {
	return buildARN(partition, "iam", "", account, resourceType, resourcePath);
}
