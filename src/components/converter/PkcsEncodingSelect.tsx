import { Select, message } from "antd";
import { ForwardedRef, forwardRef, useState } from "react";
import { error } from "tauri-plugin-log-api";
import { TextEncoding } from "../codec/codec";
import {
	ConvertRef,
	ConvertSelectProps,
	PkcsEncodingProps,
	PkcsFormat,
	PkcsFormats,
} from "./converter";

function ConvertSelectInner(
	{
		converter,
		getInputs,
		setInputs,
		value,
		onChange,
		...props
	}: ConvertSelectProps<TextEncoding, PkcsEncodingProps>,
	_: ForwardedRef<ConvertRef>
) {
	const [encoding, setEncoding] = useState<TextEncoding>(props.defaultValue);
	const [messageApi, contextHolder] = message.useMessage({
		maxCount: 1,
	});

	const selectEncoding = async (val: TextEncoding) => {
		const { privateKey, publicKey, pkcsFormat, ...parmas } = getInputs();

		const { pkcs, format } = PkcsFormats[pkcsFormat as PkcsFormat];

		const fromFormat = new PkcsEncodingProps(pkcs, format);
		const toFormat = new PkcsEncodingProps(pkcs, format);

		fromFormat.setEncoding(encoding);
		toFormat.setEncoding(val);

		try {
			const output = await converter.convert(
				privateKey as string,
				publicKey as string,
				fromFormat,
				toFormat,
				parmas
			);
			setInputs({ privateKey: output[0], publicKey: output[1] });
			setEncoding(val);
			onChange?.(val);
		} catch (err) {
			messageApi.warning("error: " + err);
			error(err as string);
		}
	};

	return (
		<>
			{contextHolder}
			<Select onChange={selectEncoding} value={value || encoding} {...props} />
		</>
	);
}

export const PkcsEncodingSelect = forwardRef(ConvertSelectInner) as <
	TextEncoding,
	PkcsEncodingProps,
>(
	props: ConvertSelectProps<TextEncoding, PkcsEncodingProps> & {
		ref?: React.ForwardedRef<ConvertRef>;
	}
) => ReturnType<typeof ConvertSelectInner>;
