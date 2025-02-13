import m, { Children, ClassComponent, Vnode, VnodeDOM } from "mithril"
import { ClickHandler } from "../GuiUtils.js"
import { assertNotNull } from "@tutao/tutanota-utils"
import { TabIndex } from "../../../api/common/TutanotaConstants.js"

// `staticRightText` to be passed as a child
export interface BaseButtonAttrs {
	/** accessibility & tooltip description */
	label: string
	/** visible text inside button */
	text?: Children
	icon?: Children
	disabled?: boolean
	pressed?: boolean
	onclick: ClickHandler
	onkeydown?: (event: KeyboardEvent) => unknown
	style?: Record<string, any>
	class?: string
	iconWrapperSelector?: string
}

export class BaseButton implements ClassComponent<BaseButtonAttrs> {
	private dom: HTMLElement | null = null

	view({ attrs, children }: Vnode<BaseButtonAttrs, this>): Children | void | null {
		const disabled = booleanToAttributeValue(attrs.disabled)
		const pressed = booleanToAttributeValue(attrs.pressed)
		return m(
			"button",
			{
				title: attrs.label,
				"aria-label": attrs.label,
				disabled,
				"aria-disabled": disabled,
				pressed,
				"aria-pressed": pressed,
				onclick: (event: MouseEvent) => attrs.onclick(event, assertNotNull(this.dom)),
				onkeydown: attrs.onkeydown,
				class: attrs.class,
				style: attrs.style,
			},
			[attrs.icon ? this.renderIcon(attrs.icon, attrs.iconWrapperSelector) : null, attrs.text ?? null, children],
		)
	}

	private renderIcon(icon: Children, selector?: string): Children {
		return m(selector ?? "span", { ariaHidden: true, tabindex: TabIndex.Programmatic }, icon)
	}

	oncreate(vnode: VnodeDOM<BaseButtonAttrs, this>): any {
		this.dom = vnode.dom as HTMLElement
	}
}

function booleanToAttributeValue(value: boolean | null | undefined): string | null {
	return value != null ? String(value) : null
}
