import { Select, message } from "antd";
import { ForwardedRef, forwardRef, useState } from "react";
import { ConvertRef } from "./converter";
import { ConvertSelectProps } from "./converter";
import { TextEncoding } from "../codec/codec";

function ConvertSelectInner(
	{
		converter,
		getInputs,
		setInputs,
		value,
		onChange,
		...props
	}: ConvertSelectProps<TextEncoding, TextEncoding>,
	_: ForwardedRef<ConvertRef>
) {
	const [encoding, setEncoding] = useState<TextEncoding>(
		value || TextEncoding.Base64
	);
	const [messageApi, contextHolder] = message.useMessage({
		maxCount: 1,
	});

	const selectEncoding = async (val: TextEncoding) => {
		const data = getInputs();
		const outputs: Record<string, unknown> = {};
		try {
			for (const k in data) {
				const d = data[k];
				const output = await converter.convert(
					d as string,
					d as string,
					encoding,
					val
				);
				outputs[k] = output;
			}
			setInputs(outputs);
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
