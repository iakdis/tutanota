import o from "@tutao/otest"
import { WorkerImpl } from "../../../../../src/api/worker/WorkerImpl.js"
import { UserFacade } from "../../../../../src/api/worker/facades/UserFacade.js"
import { GroupManagementFacade } from "../../../../../src/api/worker/facades/lazy/GroupManagementFacade.js"
import { CounterFacade } from "../../../../../src/api/worker/facades/lazy/CounterFacade.js"
import { RsaImplementation } from "../../../../../src/api/worker/crypto/RsaImplementation.js"
import { EntityClient } from "../../../../../src/api/common/EntityClient.js"
import { ServiceExecutor } from "../../../../../src/api/worker/rest/ServiceExecutor.js"
import { matchers, object, when } from "testdouble"
import {
	createMailAddressProperties,
	createMailboxGroupRoot,
	createMailboxProperties,
	MailAddressPropertiesTypeRef,
	MailboxGroupRootTypeRef,
	MailboxPropertiesTypeRef,
} from "../../../../../src/api/entities/tutanota/TypeRefs.js"
import { mapToObject } from "@tutao/tutanota-test-utils"
import {
	createGroupInfo,
	createGroupMembership,
	createMailAddressAlias,
	createUser,
	GroupInfoTypeRef,
	GroupMembershipTypeRef,
	MailAddressAliasTypeRef,
	UserTypeRef,
} from "../../../../../src/api/entities/sys/TypeRefs.js"
import { MailAddressFacade } from "../../../../../src/api/worker/facades/lazy/MailAddressFacade.js"
import { createTestEntity } from "../../../TestUtils.js"

o.spec("MailAddressFacadeTest", function () {
	let worker: WorkerImpl
	let userFacade: UserFacade
	let groupManagementFacade: GroupManagementFacade
	let countersFacade: CounterFacade
	let rsa: RsaImplementation
	let entityClient: EntityClient
	let serviceExecutor: ServiceExecutor
	let nonCachingEntityClient: EntityClient

	let facade: MailAddressFacade

	o.beforeEach(function () {
		userFacade = object()
		groupManagementFacade = object()
		serviceExecutor = object()
		nonCachingEntityClient = object()

		facade = new MailAddressFacade(userFacade, groupManagementFacade, serviceExecutor, nonCachingEntityClient)
	})

	o.spec("getSenderNames", function () {
		o("when there is existing MailboxProperties it returns the names", async function () {
			const mailGroupId = "mailGroupId"
			const viaUser = "viaUser"
			const mailboxPropertiesId = "mailboxPropertiesId"
			const mailboxGroupRoot = createTestEntity(MailboxGroupRootTypeRef, {
				_ownerGroup: mailGroupId,
				mailboxProperties: mailboxPropertiesId,
			})
			const mailGroupKey = [1, 2, 3]
			const mailboxProperties = createTestEntity(MailboxPropertiesTypeRef, {
				mailAddressProperties: [
					createTestEntity(MailAddressPropertiesTypeRef, {
						mailAddress: "a@a.com",
						senderName: "a",
					}),
					createTestEntity(MailAddressPropertiesTypeRef, {
						mailAddress: "b@b.com",
						senderName: "b",
					}),
				],
			})

			when(groupManagementFacade.getGroupKeyViaUser(mailGroupId, viaUser)).thenResolve(mailGroupKey)
			when(nonCachingEntityClient.load(MailboxGroupRootTypeRef, mailGroupId)).thenResolve(mailboxGroupRoot)
			when(nonCachingEntityClient.load(MailboxPropertiesTypeRef, mailboxPropertiesId, undefined, undefined, mailGroupKey)).thenResolve(mailboxProperties)

			const result = await facade.getSenderNames(mailGroupId, viaUser)
			o(mapToObject(result)).deepEquals({
				"a@a.com": "a",
				"b@b.com": "b",
			})
		})

		o("when there's no existing MailboxProperties it creates and returns one", async function () {
			const mailGroupId = "mailGroupId"
			const viaUser = "viaUser"
			const mailboxPropertiesId = "mailboxProeprtiesId"
			const mailboxGroupRoot = createTestEntity(MailboxGroupRootTypeRef, {
				_ownerGroup: mailGroupId,
				mailboxProperties: null,
			})
			const mailGroupKey = [1, 2, 3]
			const mailboxProperties = createTestEntity(MailboxPropertiesTypeRef, {
				_id: mailboxPropertiesId,
				_ownerGroup: mailGroupId,
				reportMovedMails: "",
				mailAddressProperties: [],
			})
			const userGroupInfoId: IdTuple = ["groupInfoListId", "groupInfoId"]
			const user = createTestEntity(UserTypeRef, {
				_id: viaUser,
				userGroup: createTestEntity(GroupMembershipTypeRef, {
					groupInfo: userGroupInfoId,
				}),
			})
			const userGroupInfo = createTestEntity(GroupInfoTypeRef, {
				_id: userGroupInfoId,
				name: "User name",
				mailAddress: "primary@example.com",
				mailAddressAliases: [
					createTestEntity(MailAddressAliasTypeRef, {
						mailAddress: "a@a.com",
						enabled: true,
					}),
				],
			})

			when(nonCachingEntityClient.load(UserTypeRef, viaUser)).thenResolve(user)
			when(nonCachingEntityClient.load(GroupInfoTypeRef, userGroupInfoId)).thenResolve(userGroupInfo)
			when(groupManagementFacade.getGroupKeyViaUser(mailGroupId, viaUser)).thenResolve(mailGroupKey)
			when(nonCachingEntityClient.load(MailboxGroupRootTypeRef, mailGroupId)).thenResolve(mailboxGroupRoot)
			when(nonCachingEntityClient.setup(null, matchers.anything(), undefined, { ownerKey: mailGroupKey })).thenResolve(mailboxPropertiesId)
			when(nonCachingEntityClient.load(MailboxPropertiesTypeRef, mailboxPropertiesId, undefined, undefined, mailGroupKey)).thenResolve(mailboxProperties)

			const result = await facade.getSenderNames(mailGroupId, viaUser)

			o(mapToObject(result)).deepEquals({
				"primary@example.com": "User name",
				"a@a.com": "User name",
			})
		})
	})
})
