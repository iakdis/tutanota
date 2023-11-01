import { CounterType, GroupType } from "../../../common/TutanotaConstants.js"
import type { ContactListGroupRoot, InternalGroupData, UserAreaGroupData } from "../../../entities/tutanota/TypeRefs.js"
import {
	createCreateMailGroupData,
	createDeleteGroupData,
	createInternalGroupData,
	createUserAreaGroupData,
	createUserAreaGroupDeleteData,
	createUserAreaGroupPostData,
} from "../../../entities/tutanota/TypeRefs.js"
import { assertNotNull, getFromMap, hexToUint8Array, neverNull } from "@tutao/tutanota-utils"
import type { Group, User } from "../../../entities/sys/TypeRefs.js"
import { createMembershipAddData, createMembershipRemoveData, GroupTypeRef, UserTypeRef } from "../../../entities/sys/TypeRefs.js"
import { CounterFacade } from "./CounterFacade.js"
import { EntityClient } from "../../../common/EntityClient.js"
import { assertWorkerOrNode } from "../../../common/Env.js"
import { encryptString } from "../../crypto/CryptoFacade.js"
import type { RsaImplementation } from "../../crypto/RsaImplementation.js"
import {
	aes128RandomKey,
	decryptKey,
	encryptKey,
	encryptRsaKey,
	rsaPublicKeyToHex,
	RsaKeyPair,
	Aes256Key,
	Versioned,
	BitArray,
	Aes128Key,
} from "@tutao/tutanota-crypto"
import { IServiceExecutor } from "../../../common/ServiceRequest.js"
import {
	CalendarService,
	ContactListGroupService,
	LocalAdminGroupService,
	MailGroupService,
	TemplateGroupService,
} from "../../../entities/tutanota/Services.js"
import { MembershipService } from "../../../entities/sys/Services.js"
import { UserFacade } from "../UserFacade.js"
import { ProgrammingError } from "../../../common/error/ProgrammingError.js"
import { DefaultEntityRestCache } from "../../rest/DefaultEntityRestCache.js"
import { getFromMapAsync } from "@tutao/tutanota-utils/dist/MapUtils.js"

assertWorkerOrNode()

export class GroupManagementFacade {
	private adminGroupKeys: Map<Id, Map<number, Aes128Key | Aes256Key>> = new Map()

	constructor(
		private readonly user: UserFacade,
		private readonly counters: CounterFacade,
		private readonly entityClient: EntityClient,
		private readonly rsa: RsaImplementation,
		private readonly serviceExecutor: IServiceExecutor,
		private readonly entityRestCache: DefaultEntityRestCache,
	) {}

	async readUsedSharedMailGroupStorage(group: Group): Promise<number> {
		return this.counters.readCounterValue(CounterType.UserStorageLegacy, neverNull(group.customer), group._id)
	}

	async createMailGroup(name: string, mailAddress: string): Promise<void> {
		let adminGroupIds = this.user.getGroupIds(GroupType.Admin)

		if (adminGroupIds.length === 0) {
			adminGroupIds = this.user.getGroupIds(GroupType.LocalAdmin)
		}

		let adminGroupKey = this.user.getGroupKey(adminGroupIds[0], undefined, this.entityClient)

		let customerGroupKey = this.user.getGroupKey(this.user.getGroupId(GroupType.Customer), undefined, this.entityClient)

		let mailGroupKey = aes128RandomKey()
		let mailGroupInfoSessionKey = aes128RandomKey()
		let mailboxSessionKey = aes128RandomKey()
		const keyPair = await this.rsa.generateKey()
		const mailGroupData = await this.generateInternalGroupData(
			keyPair,
			mailGroupKey,
			mailGroupInfoSessionKey,
			adminGroupIds[0],
			adminGroupKey,
			customerGroupKey,
		)
		const data = createCreateMailGroupData({
			mailAddress,
			encryptedName: encryptString(mailGroupInfoSessionKey, name),
			mailEncMailboxSessionKey: encryptKey(mailGroupKey, mailboxSessionKey),
			groupData: mailGroupData,
		})
		await this.serviceExecutor.post(MailGroupService, data)
	}

	/**
	 * Generates keys for the new group and prepares the group data object to create the group.
	 *
	 * @param adminGroup Is not set when generating new customer, then the admin group will be the admin of the customer
	 * @param adminGroupKey Is not set when generating calendar as normal user
	 * @param customerGroupKey Group key of the customer
	 * @param userGroupKey user group key
	 * @param name Name of the group
	 */
	generateUserAreaGroupData(name: string): Promise<UserAreaGroupData> {
		return this.entityClient.load(GroupTypeRef, this.user.getUserGroupId()).then((userGroup) => {
			const adminGroupId = neverNull(userGroup.admin) // user group has always admin group

			let adminGroupKey: BitArray | null = null

			if (this.user.getAllGroupIds().indexOf(adminGroupId) !== -1) {
				// getGroupKey throws an error if user is not member of that group - so check first
				adminGroupKey = this.user.getGroupKey(adminGroupId, undefined, this.entityClient)
			}

			const customerGroupKey = this.user.getGroupKey(this.user.getGroupId(GroupType.Customer), undefined, this.entityClient)

			const userGroupKey = this.user.getUserGroupKey(undefined, this.entityClient)

			const groupRootSessionKey = aes128RandomKey()
			const groupInfoSessionKey = aes128RandomKey()
			const groupKey = aes128RandomKey()
			return createUserAreaGroupData({
				groupEncGroupRootSessionKey: encryptKey(groupKey, groupRootSessionKey),
				customerEncGroupInfoSessionKey: encryptKey(customerGroupKey, groupInfoSessionKey),
				userEncGroupKey: encryptKey(userGroupKey, groupKey),
				groupInfoEncName: encryptString(groupInfoSessionKey, name),
				adminEncGroupKey: adminGroupKey ? encryptKey(adminGroupKey, groupKey) : null,
				adminGroup: adminGroupId,
			})
		})
	}

	async createCalendar(name: string): Promise<{ user: User; group: Group }> {
		const groupData = await this.generateUserAreaGroupData(name)
		const postData = createUserAreaGroupPostData({
			groupData,
		})
		const postGroupData = await this.serviceExecutor.post(CalendarService, postData)
		const group = await this.entityClient.load(GroupTypeRef, postGroupData.group)
		const user = await this.reloadUser()

		return { user, group }
	}

	createTemplateGroup(name: string): Promise<Id> {
		return this.generateUserAreaGroupData(name).then((groupData) => {
			const serviceData = createUserAreaGroupPostData({
				groupData: groupData,
			})
			return this.serviceExecutor.post(TemplateGroupService, serviceData).then((returnValue) => returnValue.group)
		})
	}

	async createContactListGroup(name: string): Promise<Group> {
		const groupData = await this.generateUserAreaGroupData(name)
		const serviceData = createUserAreaGroupPostData({
			groupData,
		})
		const postGroupData = await this.serviceExecutor.post(ContactListGroupService, serviceData)
		const group = await this.entityClient.load(GroupTypeRef, postGroupData.group)
		await this.reloadUser()

		return group
	}

	async deleteContactListGroup(groupRoot: ContactListGroupRoot) {
		const serviceData = createUserAreaGroupDeleteData({
			group: groupRoot._id,
		})
		await this.serviceExecutor.delete(ContactListGroupService, serviceData)
	}

	generateInternalGroupData(
		keyPair: RsaKeyPair, // FIXME change to generic keypair
		groupKey: Aes128Key,
		groupInfoSessionKey: Aes128Key,
		adminGroupId: Id | null,
		adminGroupKey: Aes128Key,
		ownerGroupKey: Aes128Key,
	): InternalGroupData {
		let groupData = createInternalGroupData()
		groupData.pubRsaKey = hexToUint8Array(rsaPublicKeyToHex(keyPair.publicKey))
		groupData.groupEncPrivRsaKey = encryptRsaKey(groupKey, keyPair.privateKey)
		groupData.pubEccKey = null
		groupData.groupEncPrivEccKey = null
		groupData.pubKyberKey = null
		groupData.groupEncPrivKyberKey = null
		groupData.adminGroup = adminGroupId
		groupData.adminEncGroupKey = encryptKey(adminGroupKey, groupKey)
		groupData.ownerEncGroupInfoSessionKey = encryptKey(ownerGroupKey, groupInfoSessionKey)
		return groupData
	}

	async addUserToGroup(user: User, groupId: Id): Promise<void> {
		const userGroupKey = await this.getGroupKeyViaAdminEncGKey(user.userGroup.group)
		const groupKey = await this.getGroupKeyViaAdminEncGKey(groupId)
		const data = createMembershipAddData({
			user: user._id,
			group: groupId,
			symEncGKey: encryptKey(userGroupKey, groupKey),
		})
		await this.serviceExecutor.post(MembershipService, data)
	}

	async removeUserFromGroup(userId: Id, groupId: Id): Promise<void> {
		const data = createMembershipRemoveData({
			user: userId,
			group: groupId,
		})
		await this.serviceExecutor.delete(MembershipService, data)
	}

	async deactivateGroup(group: Group, restore: boolean): Promise<void> {
		const data = createDeleteGroupData({
			group: group._id,
			restore,
		})

		if (group.type === GroupType.Mail) {
			await this.serviceExecutor.delete(MailGroupService, data)
		} else if (group.type === GroupType.LocalAdmin) {
			await this.serviceExecutor.delete(LocalAdminGroupService, data)
		} else {
			throw new Error("invalid group type for deactivation")
		}
	}

	/**
	 * Get a group key for any group we are admin and know some member of.
	 *
	 * Unlike {@link getGroupKeyViaAdminEncGKey} this should work for any group because we will actually go a "long" route of decrypting userGroupKey of the
	 * member and decrypting group key with that.
	 */
	async getGroupKeyViaUser(groupId: Id, viaUser: Id): Promise<Aes128Key> {
		const user = await this.entityClient.load(UserTypeRef, viaUser)
		const userGroupKey = await this.getGroupKeyViaAdminEncGKey(user.userGroup.group)
		const ship = user.memberships.find((m) => m.group === groupId)
		if (ship == null) {
			throw new Error(`User doesn't have this group membership! User: ${viaUser} groupId: ${groupId}`)
		}
		return decryptKey(userGroupKey, ship.symEncGKey)
	}

	/**
	 * Get a group key for certain group types.
	 *
	 * Some groups (e.g. user groups or shared mailboxes) have adminGroupEncGKey set on creation. For those groups we can fairly easy get a group key without
	 * decrypting userGroupKey of some member of that group.
	 */
	async getGroupKeyViaAdminEncGKey(groupId: Id): Promise<Aes128Key | Aes256Key> {
		if (this.user.hasGroup(groupId)) {
			// e.g. I am a global admin and want to add another user to the global admin group
			return (await this.user.getLatestGroupKey(groupId, this.entityClient)).object
		} else {
			const group = await this.entityClient.load(GroupTypeRef, groupId)
			if (group.adminGroupEncGKey == null || group.adminGroupEncGKey.length === 0) {
				throw new ProgrammingError("Group doesn't have adminGroupEncGKey, you can't get group key this way")
			}

			let adminGroupKey
			if (group.admin && this.user.hasGroup(group.admin)) {
				// e.g. I am a member of the group that administrates group G and want to add a new member to G
				adminGroupKey = await this.user.getGroupKey(assertNotNull(group.admin), parseInt(assertNotNull(group.adminGroupKeyVersion)), this.entityClient)
			} else {
				// e.g. I am a global admin but group G is administrated by a local admin group and want to add a new member to G
				const globalAdminGroupId = this.user.getGroupId(GroupType.Admin)
				const localAdminGroup = await this.entityClient.load(GroupTypeRef, assertNotNull(group.admin))
				const globalAdminGroupKey = await this.user.getGroupKey(
					globalAdminGroupId,
					parseInt(assertNotNull(localAdminGroup.adminGroupKeyVersion)),
					this.entityClient,
				)
				if (localAdminGroup.admin !== globalAdminGroupId) {
					throw new Error(`local admin group ${localAdminGroup._id} is not administrated by global admin group ${globalAdminGroupId}`)
				}
				if (localAdminGroup.groupKeyVersion !== group.adminGroupKeyVersion) {
					throw new Error(`the admin group key version we have is not the one we need`)
				}
				adminGroupKey = decryptKey(globalAdminGroupKey, assertNotNull(localAdminGroup.adminGroupEncGKey))
			}

			return decryptKey(adminGroupKey, assertNotNull(group.adminGroupEncGKey))
		}
	}

	private getAdminGroupKeyMap(groupId: Id): Map<number, Aes128Key | Aes256Key> {
		return getFromMap(this.adminGroupKeys, groupId, () => new Map<number, Aes128Key | Aes256Key>())
	}
	private async getAdminGroupKey(groupId: Id, version: number): Promise<Aes128Key | Aes256Key> {
		const versions = this.getAdminGroupKeyMap(groupId)
		return getFromMapAsync(versions, version, async () => {
			const group = await this.entityClient.load(GroupTypeRef, groupId)
			if (version == parseInt(group.groupKeyVersion)) {
			} else {
				// todo: load other group keys from former group keys with version as min id and go backwards to eventually decrypt it
			}
		})
	}

	/*
	 * Deletes the logged-in user from the cache, and reloads and returns the new user object.
	 * Is used to ensure we have the latest version, there can be times when the object becomes a little outdated, resulting in errors.
	 */
	async reloadUser(): Promise<User> {
		const userId = this.user.getLoggedInUser()._id

		await this.entityRestCache.deleteFromCacheIfExists(UserTypeRef, null, userId)

		const user = await this.entityClient.load(UserTypeRef, userId)
		this.user.updateUser(user)

		return user
	}
}
