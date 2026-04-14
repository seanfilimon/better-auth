import { globMatch, matchARN } from "./arn";

type ConditionValue = string | string[] | number | boolean;
type ConditionContext = Record<string, unknown>;

function toStringArray(val: ConditionValue): string[] {
	if (Array.isArray(val)) return val.map(String);
	return [String(val)];
}

function toNumber(val: unknown): number | null {
	if (typeof val === "number") return val;
	const n = Number(val);
	return Number.isNaN(n) ? null : n;
}

function toDate(val: unknown): Date | null {
	if (val instanceof Date) return val;
	if (typeof val === "string" || typeof val === "number") {
		const d = new Date(val);
		return Number.isNaN(d.getTime()) ? null : d;
	}
	return null;
}

function parseCIDR(cidr: string): { ip: bigint; mask: bigint } | null {
	const [ipStr, prefixStr] = cidr.split("/");
	if (!ipStr) return null;
	const prefix = prefixStr ? parseInt(prefixStr, 10) : 32;
	const parts = ipStr.split(".");
	if (parts.length !== 4) return null;

	let ip = 0n;
	for (const part of parts) {
		const n = parseInt(part, 10);
		if (n < 0 || n > 255 || Number.isNaN(n)) return null;
		ip = (ip << 8n) | BigInt(n);
	}

	const mask = prefix === 0 ? 0n : (~0n << BigInt(32 - prefix)) & 0xffffffffn;
	return { ip: ip & mask, mask };
}

function ipToBigInt(ipStr: string): bigint | null {
	const parts = ipStr.split(".");
	if (parts.length !== 4) return null;
	let ip = 0n;
	for (const part of parts) {
		const n = parseInt(part, 10);
		if (n < 0 || n > 255 || Number.isNaN(n)) return null;
		ip = (ip << 8n) | BigInt(n);
	}
	return ip;
}

function ipInCIDR(ip: string, cidr: string): boolean {
	const parsed = parseCIDR(cidr);
	if (!parsed) return false;
	const ipVal = ipToBigInt(ip);
	if (ipVal === null) return false;
	return (ipVal & parsed.mask) === parsed.ip;
}

const STRING_OPERATORS: Record<
	string,
	(contextVal: string, condVal: string) => boolean
> = {
	StringEquals: (c, v) => c === v,
	StringNotEquals: (c, v) => c !== v,
	StringEqualsIgnoreCase: (c, v) => c.toLowerCase() === v.toLowerCase(),
	StringNotEqualsIgnoreCase: (c, v) => c.toLowerCase() !== v.toLowerCase(),
	StringLike: (c, v) => globMatch(v, c),
	StringNotLike: (c, v) => !globMatch(v, c),
};

const NUMERIC_OPERATORS: Record<
	string,
	(contextVal: number, condVal: number) => boolean
> = {
	NumericEquals: (c, v) => c === v,
	NumericNotEquals: (c, v) => c !== v,
	NumericLessThan: (c, v) => c < v,
	NumericLessThanEquals: (c, v) => c <= v,
	NumericGreaterThan: (c, v) => c > v,
	NumericGreaterThanEquals: (c, v) => c >= v,
};

const DATE_OPERATORS: Record<
	string,
	(contextVal: Date, condVal: Date) => boolean
> = {
	DateEquals: (c, v) => c.getTime() === v.getTime(),
	DateNotEquals: (c, v) => c.getTime() !== v.getTime(),
	DateLessThan: (c, v) => c.getTime() < v.getTime(),
	DateLessThanEquals: (c, v) => c.getTime() <= v.getTime(),
	DateGreaterThan: (c, v) => c.getTime() > v.getTime(),
	DateGreaterThanEquals: (c, v) => c.getTime() >= v.getTime(),
};

function evaluateSingleCondition(
	operator: string,
	contextValue: unknown,
	conditionValue: ConditionValue,
): boolean {
	const condVals = toStringArray(conditionValue);

	if (operator in STRING_OPERATORS) {
		const fn = STRING_OPERATORS[operator]!;
		const ctxStr = String(contextValue);
		return condVals.some((v) => fn(ctxStr, v));
	}

	if (operator in NUMERIC_OPERATORS) {
		const fn = NUMERIC_OPERATORS[operator]!;
		const ctxNum = toNumber(contextValue);
		if (ctxNum === null) return false;
		return condVals.some((v) => {
			const condNum = toNumber(v);
			return condNum !== null && fn(ctxNum, condNum);
		});
	}

	if (operator in DATE_OPERATORS) {
		const fn = DATE_OPERATORS[operator]!;
		const ctxDate = toDate(contextValue);
		if (!ctxDate) return false;
		return condVals.some((v) => {
			const condDate = toDate(v);
			return condDate !== null && fn(ctxDate, condDate);
		});
	}

	if (operator === "Bool") {
		const ctxBool = String(contextValue).toLowerCase();
		return condVals.some((v) => ctxBool === v.toLowerCase());
	}

	if (operator === "IpAddress") {
		const ctxIp = String(contextValue);
		return condVals.some((v) => ipInCIDR(ctxIp, v));
	}

	if (operator === "NotIpAddress") {
		const ctxIp = String(contextValue);
		return condVals.every((v) => !ipInCIDR(ctxIp, v));
	}

	if (operator === "ArnEquals") {
		const ctxArn = String(contextValue);
		return condVals.some((v) => ctxArn === v);
	}

	if (operator === "ArnNotEquals") {
		const ctxArn = String(contextValue);
		return condVals.every((v) => ctxArn !== v);
	}

	if (operator === "ArnLike") {
		const ctxArn = String(contextValue);
		return condVals.some((v) => matchARN(v, ctxArn));
	}

	if (operator === "ArnNotLike") {
		const ctxArn = String(contextValue);
		return condVals.every((v) => !matchARN(v, ctxArn));
	}

	if (operator === "Null") {
		const isNull = contextValue === null || contextValue === undefined;
		return condVals.some((v) => (v === "true") === isNull);
	}

	return false;
}

export function evaluateConditionBlock(
	conditionBlock: Record<string, Record<string, ConditionValue>>,
	context: ConditionContext,
): boolean {
	for (const [operatorFull, conditions] of Object.entries(conditionBlock)) {
		let operator = operatorFull;
		let isForAllValues = false;
		let isForAnyValue = false;
		let isIfExists = false;

		if (operator.startsWith("ForAllValues:")) {
			isForAllValues = true;
			operator = operator.substring("ForAllValues:".length);
		} else if (operator.startsWith("ForAnyValue:")) {
			isForAnyValue = true;
			operator = operator.substring("ForAnyValue:".length);
		}

		if (operator.endsWith("IfExists")) {
			isIfExists = true;
			operator = operator.substring(0, operator.length - "IfExists".length);
		}

		for (const [key, condValue] of Object.entries(conditions)) {
			const contextValue = context[key];

			if (contextValue === undefined || contextValue === null) {
				if (isIfExists) continue;
				if (operator === "Null") {
					if (!evaluateSingleCondition("Null", contextValue, condValue)) {
						return false;
					}
					continue;
				}
				return false;
			}

			if (isForAllValues || isForAnyValue) {
				const contextArr = Array.isArray(contextValue)
					? (contextValue as unknown[])
					: [contextValue];

				if (isForAllValues) {
					const allMatch = contextArr.every((cv) =>
						evaluateSingleCondition(operator, cv, condValue),
					);
					if (!allMatch) return false;
				} else {
					const anyMatch = contextArr.some((cv) =>
						evaluateSingleCondition(operator, cv, condValue),
					);
					if (!anyMatch) return false;
				}
			} else {
				if (!evaluateSingleCondition(operator, contextValue, condValue)) {
					return false;
				}
			}
		}
	}
	return true;
}
