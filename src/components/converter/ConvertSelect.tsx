import { Select } from "antd";
import { ForwardedRef, forwardRef, useImperativeHandle, useState } from "react";
import { ConvertRef } from "./converter";
import { ConvertSelectProps } from "./converter";

function ConvertSelectInner<T>(
	props: ConvertSelectProps<T>,
	ref: ForwardedRef<ConvertRef<T>>
) {
	const [encoding, setEncoding] = useState<T>(props.props.defaultValue);

	const selectEncoding = async (value: T) => {
		const inputs = props.getInputs();
		try {
			for (const [key, input] of Object.entries(inputs)) {
				const output = await props.converter.convert(
					input,
					encoding,
					value,
					key === "publicKey"
				);
				inputs[key] = output;
			}
			props.setInputs(inputs);
			setEncoding(value);
		} catch (err: unknown) {
			console.log(err);
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

	return <Select onSelect={selectEncoding} value={encoding} {...props.props} />;
}

export const ConvertSelect = forwardRef(ConvertSelectInner) as <T>(
	props: ConvertSelectProps<T> & { ref?: React.ForwardedRef<ConvertRef<T>> }
) => ReturnType<typeof ConvertSelectInner>;
