import { Radio, RadioChangeEvent, RadioGroupProps, notification } from "antd";
import { ForwardedRef, forwardRef, useImperativeHandle, useState } from "react";

export interface Codecor<T> {
	encode: (format: T, input: Uint8Array) => Promise<string>;
	decode: (format: T, input: string) => Promise<Uint8Array>;
}

export type CodecRef<T> = {
	getFormat: () => T;
	setFormat: (format: T) => void;
};

export type CodecProps<T> = {
	props: RadioGroupProps;
	codecor: Codecor<T>;
	getInput: () => string;
	setInput: (input: string) => void;
};

function CodecInner<T>(props: CodecProps<T>, ref: ForwardedRef<CodecRef<T>>) {
	const [format, setFormat] = useState<T>(props.props.defaultValue);
	const [api, contextHolder] = notification.useNotification({
		stack: { threshold: 1 },
	});

	const openNotification = (prev: T, present: T, msg: string) => {
		api.open({
			type: "error",
			message: `change format ${prev} to ${present} failed`,
			description: msg,
			placement: "bottomRight",
			duration: 3,
		});
	};

	const changeFormat = async (event: RadioChangeEvent) => {
		props.codecor
			.decode(format, props.getInput())
			.then((bytes) =>
				props.codecor
					.encode(event.target.value, bytes)
					.then((i) => {
						props.setInput(i);
						setFormat(event.target.value);
					})
					.catch((err) => openNotification(format, event.target.value, err))
			)
			.catch((err) => openNotification(format, event.target.value, err));
	};

	useImperativeHandle(ref, () => ({
		getFormat() {
			return format;
		},
		setFormat(format: T) {
			setFormat(format);
		},
	}));

	return (
		<>
			{contextHolder}
			<Radio.Group
				onChange={changeFormat}
				value={format}
				{...props.props}
				optionType="button"
			/>
		</>
	);
}

export const Codec = forwardRef(CodecInner) as <T>(
	props: CodecProps<T> & { ref?: React.ForwardedRef<CodecRef<T>> }
) => ReturnType<typeof CodecInner>;
