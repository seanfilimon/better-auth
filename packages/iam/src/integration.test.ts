import { getTestInstance } from "better-auth/test";
import { beforeAll, describe, expect, it } from "vitest";
import { iam } from "./index";

describe("IAM Plugin integration", async () => {
	const { auth, signInWithTestUser } = await getTestInstance({
		plugins: [
			iam({
				accountId: "123456789012",
				partition: "auth",
				enforcement: { enabled: false },
				audit: { enabled: false },
			}),
		],
	});

	let headers: Headers;
	let userId: string;

	beforeAll(async () => {
		const result = await signInWithTestUser();
		headers = result.headers;
		userId = result.user.id;
	});

	describe("Policy lifecycle", () => {
		let policyId: string;

		it("should create a policy", async () => {
			const res = await auth.api.iamCreatePolicy({
				headers,
				body: {
					name: "test-policy-" + Date.now(),
					description: "Test policy",
					type: "managed",
					document: {
						Version: "2024-01-01",
						Statement: [
							{
								Effect: "Allow" as const,
								Action: "iam:GetUser",
								Resource: "*",
							},
						],
					},
				},
			});
			expect(res).toBeDefined();
			policyId = (res as any).policy?.id ?? (res as any).id;
			expect(policyId).toBeTruthy();
		});

		it("should create a policy version", async () => {
			const res = await auth.api.iamCreatePolicyVersion({
				headers,
				body: {
					policyId,
					document: {
						Version: "2024-01-01",
						Statement: [
							{
								Effect: "Allow" as const,
								Action: ["iam:GetUser", "iam:ListUsers"],
								Resource: "*",
							},
						],
					},
					setAsDefault: true,
				},
			});
			expect(res).toBeDefined();
		});

		it("should attach a policy to user", async () => {
			const res = await auth.api.iamAttachPolicy({
				headers,
				body: { policyId, targetType: "user", targetId: userId },
			});
			expect(res).toBeDefined();
		});

		it("should detach a policy from user", async () => {
			const res = await auth.api.iamDetachPolicy({
				headers,
				body: { policyId, targetType: "user", targetId: userId },
			});
			expect(res).toBeDefined();
		});

		it("should delete a policy", async () => {
			const res = await auth.api.iamDeletePolicy({
				headers,
				body: { policyId },
			});
			expect(res).toBeDefined();
		});
	});

	describe("Role lifecycle", () => {
		let roleId: string;

		it("should create a role", async () => {
			const res = await auth.api.iamCreateRole({
				headers,
				body: {
					name: "test-role-" + Date.now(),
					trustPolicy: {
						Version: "2024-01-01",
						Statement: [
							{
								Effect: "Allow" as const,
								Principal: { User: "*" },
								Action: "sts:AssumeRole",
								Resource: "*",
							},
						],
					},
				},
			});
			expect(res).toBeDefined();
			roleId = (res as any).role?.id ?? (res as any).id;
			expect(roleId).toBeTruthy();
		});

		it("should delete a role", async () => {
			const res = await auth.api.iamDeleteRole({
				headers,
				body: { roleId },
			});
			expect(res).toBeDefined();
		});
	});

	describe("Group lifecycle", () => {
		let groupId: string;

		it("should create a group", async () => {
			const res = await auth.api.iamCreateGroup({
				headers,
				body: {
					name: "test-group-" + Date.now(),
					path: "/test/",
				},
			});
			expect(res).toBeDefined();
			groupId = (res as any).group?.id ?? (res as any).id;
			expect(groupId).toBeTruthy();
		});

		it("should add user to group", async () => {
			const res = await auth.api.iamAddUserToGroup({
				headers,
				body: { groupId, userId },
			});
			expect(res).toBeDefined();
		});

		it("should remove user from group", async () => {
			const res = await auth.api.iamRemoveUserFromGroup({
				headers,
				body: { groupId, userId },
			});
			expect(res).toBeDefined();
		});

		it("should delete a group", async () => {
			const res = await auth.api.iamDeleteGroup({
				headers,
				body: { groupId },
			});
			expect(res).toBeDefined();
		});
	});

	describe("Access Key lifecycle", () => {
		let accessKeyId: string;

		it("should create an access key", async () => {
			const res = await auth.api.iamCreateAccessKey({
				headers,
				body: { userId },
			});
			expect(res).toBeDefined();
			accessKeyId =
				(res as any).accessKey?.id ??
				(res as any).accessKeyId ??
				(res as any).id;
			expect(accessKeyId).toBeTruthy();
		});

		it("should update access key status", async () => {
			const res = await auth.api.iamUpdateAccessKeyStatus({
				headers,
				body: { accessKeyId, status: "inactive" },
			});
			expect(res).toBeDefined();
		});

		it("should delete an access key", async () => {
			const res = await auth.api.iamDeleteAccessKey({
				headers,
				body: { accessKeyId },
			});
			expect(res).toBeDefined();
		});
	});
});
