import { Select, message } from "antd";
import { ForwardedRef, forwardRef, useImperativeHandle, useState } from "react";
import {
	ConvertRef,
	Pkcs1Encoding,
	Pkcs8Encoding,
	PkcsEncoding,
	PkcsEncodings,
	Sec1Encoding,
} from "./converter";
import { ConvertSelectProps } from "./converter";
import { TextEncoding } from "../codec/codec";

function ConvertSelectInner<T extends PkcsEncoding>(
	{
		converter,
		getInputs,
		setInputs,
		textEncoding,
		...props
	}: ConvertSelectProps<T>,
	ref: ForwardedRef<ConvertRef<T>>
) {
	const [encoding, setEncoding] = useState<T>(props.defaultValue);
	const [messageApi, contextHolder] = message.useMessage({
		maxCount: 1,
	});
	const ders = [
		Pkcs1Encoding.PKCS1_DER,
		Pkcs8Encoding.PKCS8_DER,
		Sec1Encoding.SEC1_DER,
	];
	const selectEncoding = async (value: T) => {
		console.log(textEncoding, value, encoding);
		if (textEncoding === TextEncoding.UTF8) {
			const pkcs = ders.includes(encoding)
				? PkcsEncodings[encoding]
				: ders.includes(value)
					? PkcsEncodings[value]
					: null;
			if (pkcs) {
				messageApi.warning({
					content: (
						<span>
							Incompatible text encodings(
							<span style={{ fontWeight: 700 }}>{textEncoding}</span>) and key
							formats(
							{<span style={{ fontWeight: 700 }}>{pkcs.encoding}</span>})
						</span>
					),
					duration: 5,
				});
				return;
			}
		}

		const inputs = getInputs();
		try {
			for (const [key, inputStr] of Object.entries(inputs)) {
				const input = await converter.textCodecor.decode(
					textEncoding,
					inputStr
				);
				const output = await converter.convert(
					input,
					encoding,
					value,
					key === "publicKey"
				);
				inputs[key] = await converter.textCodecor.encode(textEncoding, output);
			}
			setInputs(inputs);

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
	}));

	return (
		<>
			{contextHolder}
			<Select onSelect={selectEncoding} value={encoding} {...props} />
		</>
	);
}

export const ConvertSelect = forwardRef(ConvertSelectInner) as <
	T extends PkcsEncoding,
>(
	props: ConvertSelectProps<T> & { ref?: React.ForwardedRef<ConvertRef<T>> }
) => ReturnType<typeof ConvertSelectInner>;
