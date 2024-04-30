import { Radio, RadioChangeEvent, notification } from "antd";
import { ForwardedRef, forwardRef, useImperativeHandle, useState } from "react";
import { CodecRadioProps, CodecRef } from "./codec";

function CodecRadioInner<T>(
	props: CodecRadioProps<T>,
	ref: ForwardedRef<CodecRef<T>>
) {
	const [encoding, setEncoding] = useState<T>(props.props.defaultValue);
	const [api, contextHolder] = notification.useNotification({
		stack: { threshold: 1 },
	});

	const openNotification = (prev: T, present: T, msg: string) => {
		api.open({
			type: "error",
			message: `change encoding ${prev} to ${present} failed`,
			description: msg,
			placement: "bottomRight",
			duration: 3,
		});
	};

	const changeEncoding = async (event: RadioChangeEvent) => {
		const inputs = props.getInputs();
		try {
			for (const [key, input] of Object.entries(inputs)) {
				const decoded = await props.codecor.decode(encoding, input);

				const encoded = await props.codecor.encode(event.target.value, decoded);
				inputs[key] = encoded;
			}
			props.setInputs(inputs);
			props.callback && props.callback(event.target.value);
			setEncoding(event.target.value);
		} catch (err: unknown) {
			openNotification(encoding, event.target.value, err as string);
		}
	};

	useImperativeHandle(ref, () => ({
		getEncoding() {
			return encoding;
		},
		setEncoding(encoding: T) {
			setEncoding(encoding);
		},
	}));

	return (
		<>
			{contextHolder}
			<Radio.Group
				onChange={changeEncoding}
				value={encoding}
				{...props.props}
				optionType="button"
			/>
		</>
	);
}

export const CodecRadio = forwardRef(CodecRadioInner) as <T>(
	props: CodecRadioProps<T> & { ref?: React.ForwardedRef<CodecRef<T>> }
) => ReturnType<typeof CodecRadioInner>;
