/* generated file, don't edit. */

import { MobileSystemFacade } from "./MobileSystemFacade.js"

interface NativeInterface {
	invokeNative(requestType: string, args: unknown[]): Promise<any>
}
export class MobileSystemFacadeSendDispatcher implements MobileSystemFacade {
	constructor(private readonly transport: NativeInterface) {}
	async findSuggestions(...args: Parameters<MobileSystemFacade["findSuggestions"]>) {
		return this.transport.invokeNative("ipc", ["MobileSystemFacade", "findSuggestions", ...args])
	}
	async saveContacts(...args: Parameters<MobileSystemFacade["saveContacts"]>) {
		return this.transport.invokeNative("ipc", ["MobileSystemFacade", "saveContacts", ...args])
	}
	async syncContacts(...args: Parameters<MobileSystemFacade["syncContacts"]>) {
		return this.transport.invokeNative("ipc", ["MobileSystemFacade", "syncContacts", ...args])
	}
	async deleteContacts(...args: Parameters<MobileSystemFacade["deleteContacts"]>) {
		return this.transport.invokeNative("ipc", ["MobileSystemFacade", "deleteContacts", ...args])
	}
	async goToSettings(...args: Parameters<MobileSystemFacade["goToSettings"]>) {
		return this.transport.invokeNative("ipc", ["MobileSystemFacade", "goToSettings", ...args])
	}
	async openLink(...args: Parameters<MobileSystemFacade["openLink"]>) {
		return this.transport.invokeNative("ipc", ["MobileSystemFacade", "openLink", ...args])
	}
	async shareText(...args: Parameters<MobileSystemFacade["shareText"]>) {
		return this.transport.invokeNative("ipc", ["MobileSystemFacade", "shareText", ...args])
	}
}
