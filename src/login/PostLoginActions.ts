import m, { Component } from "mithril"
import type { LoggedInEvent, PostLoginAction } from "../api/main/LoginController"
import { LoginController } from "../api/main/LoginController"
import { isAdminClient, isApp, isDesktop, LOGIN_TITLE } from "../api/common/Env"
import { assertNotNull, neverNull, noOp, ofClass } from "@tutao/tutanota-utils"
import { windowFacade } from "../misc/WindowFacade"
import { checkApprovalStatus } from "../misc/LoginUtils"
import { locator } from "../api/main/MainLocator"
import { ReceiveInfoService } from "../api/entities/tutanota/Services"
import { lang } from "../misc/LanguageViewModel"
import { getHourCycle } from "../misc/Formatter"
import { createReceiveInfoServiceData, OutOfOfficeNotification } from "../api/entities/tutanota/TypeRefs.js"
import { isNotificationCurrentlyActive, loadOutOfOfficeNotification } from "../misc/OutOfOfficeNotificationUtils"
import * as notificationOverlay from "../gui/base/NotificationOverlay"
import { ButtonType } from "../gui/base/Button.js"
import { themeController } from "../gui/theme"
import { Dialog } from "../gui/base/Dialog"
import { CloseEventBusOption, Const, SecondFactorType } from "../api/common/TutanotaConstants"
import { showMoreStorageNeededOrderDialog } from "../misc/SubscriptionDialogs"
import { notifications } from "../gui/Notifications"
import { LockedError } from "../api/common/error/RestError"
import type { CredentialsProvider } from "../misc/credentials/CredentialsProvider.js"
import { usingKeychainAuthenticationWithOptions } from "../misc/credentials/CredentialsProviderFactory"
import type { ThemeCustomizations } from "../misc/WhitelabelCustomizations"
import { getThemeCustomizations } from "../misc/WhitelabelCustomizations"
import { CredentialEncryptionMode } from "../misc/credentials/CredentialEncryptionMode"
import { SecondFactorHandler } from "../misc/2fa/SecondFactorHandler"
import { SessionType } from "../api/common/SessionType"
import { StorageBehavior } from "../misc/UsageTestModel.js"
import type { WebsocketConnectivityModel } from "../misc/WebsocketConnectivityModel.js"
import { DateProvider } from "../api/common/DateProvider.js"
import { createCustomerProperties, SecondFactorTypeRef } from "../api/entities/sys/TypeRefs.js"
import { EntityClient } from "../api/common/EntityClient.js"
import { shouldShowStorageWarning, shouldShowUpgradeReminder } from "./PostLoginUtils.js"
import { UserManagementFacade } from "../api/worker/facades/lazy/UserManagementFacade.js"
import { CustomerFacade } from "../api/worker/facades/lazy/CustomerFacade.js"

/**
 * This is a collection of all things that need to be initialized/global state to be set after a user has logged in successfully.
 */

export class PostLoginActions implements PostLoginAction {
	constructor(
		private readonly credentialsProvider: CredentialsProvider,
		public secondFactorHandler: SecondFactorHandler,
		private readonly connectivityModel: WebsocketConnectivityModel,
		private readonly logins: LoginController,
		private readonly dateProvider: DateProvider,
		private readonly entityClient: EntityClient,
		private readonly userManagementFacade: UserManagementFacade,
		private readonly customerFacade: CustomerFacade,
	) {}

	async onPartialLoginSuccess(loggedInEvent: LoggedInEvent): Promise<void> {
		// We establish websocket connection even for temporary sessions because we need to get updates e.g. during signup
		windowFacade.addOnlineListener(() => {
			console.log(new Date().toISOString(), "online - try reconnect")
			if (this.logins.isFullyLoggedIn()) {
				// When we try to connect after receiving online event it might not succeed so we delay reconnect attempt by 2s
				this.connectivityModel.tryReconnect(true, true, 2000)
			} else {
				// log in user
				this.logins.retryAsyncLogin()
			}
		})
		windowFacade.addOfflineListener(() => {
			console.log(new Date().toISOString(), "offline - pause event bus")
			this.connectivityModel.close(CloseEventBusOption.Pause)
		})

		// only show "Tuta Mail" after login if there is no custom title set
		if (!this.logins.getUserController().isInternalUser()) {
			if (document.title === LOGIN_TITLE) {
				document.title = "Tuta Mail"
			}

			return
		} else {
			let postLoginTitle = document.title === LOGIN_TITLE ? "Tuta Mail" : document.title
			document.title = neverNull(this.logins.getUserController().userGroupInfo.mailAddress) + " - " + postLoginTitle
		}
		notifications.requestPermission()

		if (
			loggedInEvent.sessionType === SessionType.Persistent &&
			usingKeychainAuthenticationWithOptions() &&
			this.credentialsProvider.getCredentialsEncryptionMode() == null
		) {
			// If the encryption mode is not selected, we opt user into automatic mode.
			// We keep doing it here for now to have some flexibility if we want to show some other option here in the future.
			await this.credentialsProvider.setCredentialsEncryptionMode(CredentialEncryptionMode.DEVICE_LOCK)
		}

		lang.updateFormats({
			// partial
			hourCycle: getHourCycle(this.logins.getUserController().userSettingsGroupRoot),
		})

		if (isApp()) {
			// don't wait for it, just invoke
			locator.fileApp.clearFileData().catch((e) => console.log("Failed to clean file data", e))
			locator.nativeContactsSyncManager()?.syncContacts()
		}
	}

	async onFullLoginSuccess(loggedInEvent: LoggedInEvent): Promise<void> {
		if (loggedInEvent.sessionType === SessionType.Temporary || !this.logins.getUserController().isInternalUser()) {
			return
		}

		// Do not wait
		this.fullLoginAsyncActions()
	}

	private async fullLoginAsyncActions() {
		await checkApprovalStatus(this.logins, true)
		await this.showUpgradeReminderIfNeeded()
		await this.checkStorageLimit()

		this.secondFactorHandler.setupAcceptOtherClientLoginListener()

		if (!isAdminClient()) {
			// If it failed during the partial login due to missing cache entries we will give it another spin here. If it didn't fail then it's just a noop
			await locator.mailModel.init()
			const calendarModel = await locator.calendarModel()
			await calendarModel.init()
			await this.remindActiveOutOfOfficeNotification()
		}

		if (isApp() || isDesktop()) {
			locator.pushService.register()
			await this.maybeSetCustomTheme()
		}

		if (this.logins.isGlobalAdminUserLoggedIn() && !isAdminClient()) {
			const receiveInfoData = createReceiveInfoServiceData({
				language: lang.code,
			})
			locator.serviceExecutor.post(ReceiveInfoService, receiveInfoData)
		}

		this.enforcePasswordChange()

		const usageTestModel = locator.usageTestModel
		await usageTestModel.init()

		usageTestModel.setStorageBehavior(StorageBehavior.Persist)
		// Load only up-to-date (not older than 1h) assignments here and make a request for that.
		// There should not be a lot of re-rendering at this point since assignments for new tests are usually fetched right after a client version update.
		locator.usageTestController.setTests(await usageTestModel.loadActiveUsageTests())

		// Needs to be called after UsageTestModel.init() if the UsageOptInNews is live! (its isShown() requires an initialized UsageTestModel)
		await locator.newsModel.loadNewsIds()

		// Redraw to render usage tests and news, among other things that may have changed.
		m.redraw()
	}

	private deactivateOutOfOfficeNotification(notification: OutOfOfficeNotification): Promise<void> {
		notification.enabled = false
		return this.entityClient.update(notification)
	}

	private remindActiveOutOfOfficeNotification(): Promise<void> {
		return loadOutOfOfficeNotification().then((notification) => {
			if (notification && isNotificationCurrentlyActive(notification, new Date())) {
				const notificationMessage: Component = {
					view: () => {
						return m("", lang.get("outOfOfficeReminder_label"))
					},
				}
				notificationOverlay.show(
					notificationMessage,
					{
						label: "close_alt",
					},
					[
						{
							label: "deactivate_action",
							click: () => this.deactivateOutOfOfficeNotification(notification),
							type: ButtonType.Primary,
						},
					],
				)
			}
		})
	}

	private async maybeSetCustomTheme(): Promise<any> {
		const domainInfoAndConfig = await this.logins.getUserController().loadWhitelabelConfig()

		if (domainInfoAndConfig && domainInfoAndConfig.whitelabelConfig.jsonTheme) {
			const customizations: ThemeCustomizations = getThemeCustomizations(domainInfoAndConfig.whitelabelConfig)

			// jsonTheme is stored on WhitelabelConfig as an empty json string ("{}", or whatever JSON.stringify({}) gives you)
			// so we can't just check `!whitelabelConfig.jsonTheme`
			if (Object.keys(customizations).length > 0) {
				const themeId = (customizations.themeId = domainInfoAndConfig.domainInfo.domain)
				const previouslySavedThemes = await themeController.getCustomThemes()
				await themeController.storeCustomThemeForCustomizations(customizations)
				const isExistingTheme = previouslySavedThemes.includes(domainInfoAndConfig.domainInfo.domain)

				if (!isExistingTheme && (await Dialog.confirm("whitelabelThemeDetected_msg"))) {
					await themeController.setThemePreference(themeId)
				} else {
					// If the theme has changed we want to reload it, otherwise this is no-op
					await themeController.reloadTheme()
				}
			}
		}
	}

	private async checkStorageLimit(): Promise<void> {
		if (await shouldShowStorageWarning(this.logins.getUserController(), this.userManagementFacade, this.customerFacade)) {
			await showMoreStorageNeededOrderDialog("insufficientStorageWarning_msg")
		}
	}

	private async showUpgradeReminderIfNeeded(): Promise<void> {
		if (await shouldShowUpgradeReminder(this.logins.getUserController(), new Date(this.dateProvider.now()))) {
			const confirmed = await Dialog.reminder(lang.get("upgradeReminderTitle_msg"), lang.get("premiumOffer_msg"))
			if (confirmed) {
				const wizard = await import("../subscription/UpgradeSubscriptionWizard")
				await wizard.showUpgradeWizard(this.logins)
			}

			const newCustomerProperties = createCustomerProperties(await this.logins.getUserController().loadCustomerProperties())
			newCustomerProperties.lastUpgradeReminder = new Date(this.dateProvider.now())
			this.entityClient.update(newCustomerProperties).catch(ofClass(LockedError, noOp))
		}
	}

	private async enforcePasswordChange(): Promise<void> {
		if (this.logins.getUserController().user.requirePasswordUpdate) {
			const { showChangeOwnPasswordDialog } = await import("../settings/login/ChangePasswordDialogs.js")
			await showChangeOwnPasswordDialog(false)
		}

		if (location.hostname === Const.DEFAULT_APP_DOMAIN) {
			const user = this.logins.getUserController().user
			const secondFactors = await this.entityClient.loadAll(SecondFactorTypeRef, assertNotNull(user.auth).secondFactors)
			const webauthnFactors = secondFactors.filter((f) => f.type === SecondFactorType.webauthn || f.type === SecondFactorType.u2f)
			// If there are webauthn factors but none of them are for the default domain, show a message
			if (webauthnFactors.length > 0 && !webauthnFactors.some((f) => f.u2f && f.u2f?.appId == Const.WEBAUTHN_RP_ID)) {
				const dialog = Dialog.confirmMultiple("noKeysForThisDomain_msg", [
					{
						label: "skip_action",
						type: ButtonType.Secondary,
						click: () => dialog.close(),
					},
					{
						label: "settings_label",
						type: ButtonType.Primary,
						click: () => {
							dialog.close()
							m.route.set("/settings/login")
						},
					},
				])
			}
		}
	}
}
