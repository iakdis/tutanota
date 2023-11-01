import { GroupType } from "../../common/TutanotaConstants"
import { Aes128Key, Aes256Key, decryptKey, Versioned } from "@tutao/tutanota-crypto"
import { assertNotNull, base64ToBase64Url, getFromMap, neverNull, stringToBase64 } from "@tutao/tutanota-utils"
import { ProgrammingError } from "../../common/error/ProgrammingError"
import { createWebsocketLeaderStatus, GroupKeyTypeRef, GroupMembership, GroupTypeRef, User, WebsocketLeaderStatus } from "../../entities/sys/TypeRefs"
import { LoginIncompleteError } from "../../common/error/LoginIncompleteError"
import { getFromMapAsync } from "@tutao/tutanota-utils/dist/MapUtils.js"
import { EntityClient } from "../../common/EntityClient.js"
import { NotFoundError } from "../../common/error/RestError.js"

export interface AuthDataProvider {
	/**
	 * @return The map which contains authentication data for the logged in user.
	 */
	createAuthHeaders(): Dict

	isFullyLoggedIn(): boolean
}

/** Holder for the user and session-related data on the worker side. */
export class UserFacade implements AuthDataProvider {
	private user: User | null = null
	private accessToken: string | null = null
	/**
	 * A cache for decrypted keys of each group. Encrypted keys are stored on membership.symEncGKey.
	 *
	 * Instances are mapped from group ID to a map of versions to decrypted keys
	 */
	private groupKeys: Map<Id, Map<number, Aes128Key | Aes256Key>> = new Map()
	private leaderStatus!: WebsocketLeaderStatus

	constructor() {
		this.reset()
	}

	// Login process is somehow multi-step and we don't use a separate network stack for it. So we have to break up setters.
	// 1. We need to download user. For that we need to set access token already (to authenticate the request for the server as its passed in headers).
	// 2. We need to get group keys. For that we need to unlock userGroupKey with userPasspharseKey
	// so this leads to this steps in UserFacade:
	// 1. Access token is set
	// 2. User is set
	// 3. UserGroupKey is unlocked
	setAccessToken(accessToken: string | null) {
		this.accessToken = accessToken
	}

	setUser(user: User) {
		if (this.accessToken == null) {
			throw new ProgrammingError("invalid state: no access token")
		}
		this.user = user
	}

	unlockUserGroupKey(userPassphraseKey: Aes128Key) {
		if (this.user == null) {
			throw new ProgrammingError("Invalid state: no user")
		}
		this.getGroupKeyMap(this.getUserGroupId()).set(
			parseInt(neverNull(this.user.userGroup.groupKeyVersion)),
			decryptKey(userPassphraseKey, this.user.userGroup.symEncGKey),
		)
	}

	updateUser(user: User) {
		if (this.user == null) {
			throw new ProgrammingError("Update user is called without logging in. This function is not for you.")
		}
		this.user = user
	}

	getUser(): User | null {
		return this.user
	}

	/**
	 * @return The map which contains authentication data for the logged in user.
	 */
	createAuthHeaders(): Dict {
		return this.accessToken
			? {
					accessToken: this.accessToken,
			  }
			: {}
	}

	getUserGroupId(): Id {
		return this.getLoggedInUser().userGroup.group
	}

	getAllGroupIds(): Id[] {
		let groups = this.getLoggedInUser().memberships.map((membership) => membership.group)
		groups.push(this.getLoggedInUser().userGroup.group)
		return groups
	}

	getUserGroupKey(version: number, entityClient: EntityClient): Promise<Aes128Key | Aes256Key> {
		// the userGroupKey is always written after the login to this.groupKeys
		//if the user has only logged in offline this has not happened
		let userGroupId = this.getUserGroupId()
		const userGroupKeys = this.groupKeys.get(userGroupId)
		if (userGroupKeys == null) {
			if (this.isPartiallyLoggedIn()) {
				throw new LoginIncompleteError("userGroupKey not available")
			} else {
				throw new ProgrammingError("Invalid state: userGroupKey is not available")
			}
		}
		return this.getGroupKey(userGroupId, version, entityClient)
	}

	async getGroupKey(groupId: Id, version: number, entityClient: EntityClient): Promise<Aes128Key | Aes256Key> {
		const groupKeys = this.getGroupKeyMap(groupId)
		return getFromMapAsync(groupKeys, version, async () => await this.retrieveGroupKey(groupId, entityClient, version))
	}

	private async retrieveGroupKey(groupId: string, entityClient: EntityClient, version: number): Promise<Aes128Key | Aes256Key> {
		if (version != null) {
			const result = await this.retrieveGroupKeyFromMembership(groupId, entityClient, version)
			if (result) {
				return result.object
			}
		}

		const group = await entityClient.load(GroupTypeRef, groupId)
		const list = group.formerGroupKeys?.list
		if (list == null) {
			throw new NotFoundError(`no former group key list found for group ${groupId}`)
		}

		const groupKeyInstance = await entityClient.load(GroupKeyTypeRef, [list, base64ToBase64Url(stringToBase64(version.toString()))])
		const encryptingKey = await this.getGroupKey(groupId, parseInt(groupKeyInstance.ownerKeyVersion), entityClient)
		return decryptKey(encryptingKey, groupKeyInstance.ownerEncGKey)
	}

	private async retrieveGroupKeyFromMembership(
		groupId: string,
		entityClient: EntityClient,
		versionToCheck?: number,
	): Promise<Versioned<Aes128Key | Aes256Key> | null> {
		const membership = this.getMembership(groupId)
		const userGroupKey = await this.getUserGroupKey(parseInt(membership.symKeyVersion), entityClient)
		const groupKeyVersionInMembership = parseInt(membership.groupKeyVersion)
		if (versionToCheck != null && versionToCheck !== groupKeyVersionInMembership) {
			return null
		}
		return { object: decryptKey(userGroupKey, membership.symEncGKey), version: groupKeyVersionInMembership }
	}

	async getLatestGroupKey(groupId: Id, entityClient: EntityClient): Promise<Versioned<Aes128Key | Aes256Key>> {
		return neverNull(await this.retrieveGroupKeyFromMembership(groupId, entityClient))
	}

	getMembership(groupId: Id): GroupMembership {
		let membership = this.getLoggedInUser().memberships.find((g: GroupMembership) => g.group === groupId)

		if (!membership) {
			throw new Error(`No group with groupId ${groupId} found!`)
		}

		return membership
	}

	hasGroup(groupId: Id): boolean {
		if (!this.user) {
			return false
		} else {
			return groupId === this.user.userGroup.group || this.user.memberships.some((m) => m.group === groupId)
		}
	}

	getGroupId(groupType: GroupType): Id {
		if (groupType === GroupType.User) {
			return this.getUserGroupId()
		} else {
			let membership = this.getLoggedInUser().memberships.find((m) => m.groupType === groupType)

			if (!membership) {
				throw new Error("could not find groupType " + groupType + " for user " + this.getLoggedInUser()._id)
			}

			return membership.group
		}
	}

	getGroupIds(groupType: GroupType): Id[] {
		return this.getLoggedInUser()
			.memberships.filter((m) => m.groupType === groupType)
			.map((gm) => gm.group)
	}

	isPartiallyLoggedIn(): boolean {
		return this.user != null
	}

	isFullyLoggedIn(): boolean {
		// We have userGroupKey and we can decrypt any other key - we are good to go
		return this.groupKeys.size > 0
	}

	getLoggedInUser(): User {
		return assertNotNull(this.user)
	}

	setLeaderStatus(status: WebsocketLeaderStatus) {
		this.leaderStatus = status
		console.log("New leader status set:", status.leaderStatus)
	}

	isLeader(): boolean {
		return this.leaderStatus.leaderStatus
	}

	reset() {
		this.user = null
		this.accessToken = null
		this.groupKeys = new Map()
		this.leaderStatus = createWebsocketLeaderStatus({
			leaderStatus: false,
		})
	}

	private getGroupKeyMap(groupId: Id): Map<number, Aes128Key | Aes256Key> {
		return getFromMap(this.groupKeys, groupId, () => new Map<number, Aes128Key | Aes256Key>())
	}
}
