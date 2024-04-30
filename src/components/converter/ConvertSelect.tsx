import { Select } from "antd";
import { ForwardedRef, forwardRef, useImperativeHandle, useState } from "react";
import { ConvertRef } from "./converter";
import { ConvertSelectProps } from "./converter";
import { TextEncoding } from "../codec/codec";

function ConvertSelectInner<T>(
	props: ConvertSelectProps<T>,
	ref: ForwardedRef<ConvertRef<T>>
) {
	const [encoding, setEncoding] = useState<T>(props.props.defaultValue);
	const [textEncoding, setTextEncoding] = useState<TextEncoding>(
		TextEncoding.UTF8
	);

	const selectEncoding = async (value: T) => {
		const inputs = props.getInputs();
		try {
			for (const [key, inputStr] of Object.entries(inputs)) {
				console.log(inputStr);
				const input = await props.converter.textCodecor.decode(
					textEncoding,
					inputStr
				);
				console.log(input);

				const output = await props.converter.convert(
					input,
					encoding,
					value,
					key === "publicKey"
				);
				inputs[key] = await props.converter.textCodecor.encode(
					textEncoding,
					output
				);
			}
			props.setInputs(inputs);
			setEncoding(value);
		} catch (err) {
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
		getTextEncoding() {
			return textEncoding;
		},
		setTextEncoding(encoding: TextEncoding) {
			setTextEncoding(encoding);
		},
	}));

	return <Select onSelect={selectEncoding} value={encoding} {...props.props} />;
}

export const ConvertSelect = forwardRef(ConvertSelectInner) as <T>(
	props: ConvertSelectProps<T> & { ref?: React.ForwardedRef<ConvertRef<T>> }
) => ReturnType<typeof ConvertSelectInner>;
