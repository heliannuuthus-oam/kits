import { Select, notification } from "antd";
import { ForwardedRef, forwardRef, useImperativeHandle, useState } from "react";
import { CodecRef } from "./codec";
import { CodecSelectProps } from "./codec";

function CodecSelectInner<T>(
	props: CodecSelectProps<T>,
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

	const selectEncoding = async (value: T) => {
		const inputs = props.getInputs();
		try {
			for (const [key, input] of Object.entries(inputs)) {
				const decoded = await props.codecor.decode(encoding, input);

				const encoded = await props.codecor.encode(value, decoded);
				inputs[key] = encoded;
			}
			props.setInputs(inputs);
			props.callback && props.callback(value);
			setEncoding(value);
		} catch (err: unknown) {
			openNotification(encoding, value, err as string);
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
			<Select onSelect={selectEncoding} value={encoding} {...props.props} />
		</>
	);
}

export const CodecSelect = forwardRef(CodecSelectInner) as <T>(
	props: CodecSelectProps<T> & { ref?: React.ForwardedRef<CodecRef<T>> }
) => ReturnType<typeof CodecSelectInner>;
