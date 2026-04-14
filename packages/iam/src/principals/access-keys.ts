import type { IamAdapter } from "../adapter";
import {
	ACCESS_KEY_ID_LENGTH,
	ACCESS_KEY_PREFIX_LONG_TERM,
	SECRET_KEY_LENGTH,
} from "../constants";
import { IAM_ERROR_CODES } from "../error-codes";
import {
	constantTimeEqual,
	generateRandomString,
	hmacHash,
} from "../utils/crypto";

export async function createAccessKey(
	iamAdapter: IamAdapter,
	userId: string,
	maxKeysPerUser: number,
) {
	const existing = await iamAdapter.countAccessKeysByUser(userId);
	if (existing >= maxKeysPerUser) {
		throw new Error(IAM_ERROR_CODES.ACCESS_KEY_LIMIT_EXCEEDED.message);
	}

	const accessKeyId =
		ACCESS_KEY_PREFIX_LONG_TERM +
		generateRandomString(
			ACCESS_KEY_ID_LENGTH - ACCESS_KEY_PREFIX_LONG_TERM.length,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		);
	const secretAccessKey = generateRandomString(
		SECRET_KEY_LENGTH,
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	);
	const secretKeyHash = await hmacHash(
		"iam-access-key-secret",
		secretAccessKey,
	);

	const key = await iamAdapter.createAccessKey({
		id: accessKeyId,
		secretKeyHash,
		userId,
		status: "active",
	});

	return {
		accessKeyId,
		secretAccessKey,
		key,
	};
}

export async function deleteAccessKey(
	iamAdapter: IamAdapter,
	accessKeyId: string,
	requestingUserId?: string,
) {
	const key = await iamAdapter.findAccessKeyById(accessKeyId);
	if (!key) {
		throw new Error(IAM_ERROR_CODES.ACCESS_KEY_NOT_FOUND.message);
	}
	if (requestingUserId && (key as any).userId !== requestingUserId) {
		throw new Error(IAM_ERROR_CODES.AUTHORIZATION_DENIED.message);
	}
	await iamAdapter.deleteAccessKey(accessKeyId);
}

export async function updateAccessKeyStatus(
	iamAdapter: IamAdapter,
	accessKeyId: string,
	status: "active" | "inactive",
) {
	const key = await iamAdapter.findAccessKeyById(accessKeyId);
	if (!key) {
		throw new Error(IAM_ERROR_CODES.ACCESS_KEY_NOT_FOUND.message);
	}
	return iamAdapter.updateAccessKey(accessKeyId, { status });
}

export async function listAccessKeys(iamAdapter: IamAdapter, userId: string) {
	return iamAdapter.listAccessKeysByUser(userId);
}

export async function getAccessKeyLastUsed(
	iamAdapter: IamAdapter,
	accessKeyId: string,
) {
	const key = await iamAdapter.findAccessKeyById(accessKeyId);
	if (!key) {
		throw new Error(IAM_ERROR_CODES.ACCESS_KEY_NOT_FOUND.message);
	}
	return {
		lastUsedAt: (key as any).lastUsedAt,
		lastUsedService: (key as any).lastUsedService,
		lastUsedRegion: (key as any).lastUsedRegion,
	};
}

export async function verifyAccessKeySecret(
	iamAdapter: IamAdapter,
	accessKeyId: string,
	providedSecret: string,
): Promise<boolean> {
	const key = await iamAdapter.findAccessKeyById(accessKeyId);
	if (!key) return false;
	if ((key as any).status !== "active") return false;

	const providedHash = await hmacHash("iam-access-key-secret", providedSecret);
	return constantTimeEqual(providedHash, (key as any).secretKeyHash);
}

export async function recordAccessKeyUsage(
	iamAdapter: IamAdapter,
	accessKeyId: string,
	service?: string,
	region?: string,
) {
	await iamAdapter.updateAccessKey(accessKeyId, {
		lastUsedAt: new Date(),
		lastUsedService: service,
		lastUsedRegion: region,
	});
}
