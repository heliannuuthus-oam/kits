import { Select, message } from "antd";
import { forwardRef, useState } from "react";
import { ConvertRef } from "./converter";
import { ConvertSelectProps } from "./converter";
import { TextEncoding } from "../codec/codec";

function ConvertSelectInner({
	converter,
	getInputs,
	setInputs,
	value,
	onChange,
	...props
}: ConvertSelectProps<TextEncoding, TextEncoding>) {
	const [encoding, setEncoding] = useState<TextEncoding>(props.defaultValue);
	const [messageApi, contextHolder] = message.useMessage({
		maxCount: 1,
	});

	const selectEncoding = async (val: TextEncoding) => {
		const { privateKey, publicKey } = getInputs();

		try {
			const output = await converter.convert(
				privateKey as string,
				publicKey as string,
				encoding,
				val
			);
			setInputs({ output: output });
			setEncoding(val);
			onChange?.(val);
		} catch (err) {
			messageApi.warning("error: " + err);
			console.log(err);
		}
	};

	return (
		<>
			{contextHolder}
			<Select onChange={selectEncoding} value={value || encoding} {...props} />
		</>
	);
}

export const TextEncodingSelect = forwardRef(ConvertSelectInner) as <
	TextEncoding,
>(
	props: ConvertSelectProps<TextEncoding, TextEncoding> & {
		ref?: React.ForwardedRef<ConvertRef>;
	}
) => ReturnType<typeof ConvertSelectInner>;
