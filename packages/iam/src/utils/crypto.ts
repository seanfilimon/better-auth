export function generateRandomString(length: number, charset: string): string {
	const maxUsable = 256 - (256 % charset.length);
	const result: string[] = [];
	while (result.length < length) {
		const arr = new Uint8Array(length * 2);
		crypto.getRandomValues(arr);
		for (const b of arr) {
			if (b < maxUsable && result.length < length) {
				result.push(charset[b % charset.length]!);
			}
		}
	}
	return result.join("");
}

export async function hmacHash(key: string, data: string): Promise<string> {
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(key),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const signature = await crypto.subtle.sign(
		"HMAC",
		cryptoKey,
		new TextEncoder().encode(data),
	);
	return Array.from(new Uint8Array(signature))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return result === 0;
}
