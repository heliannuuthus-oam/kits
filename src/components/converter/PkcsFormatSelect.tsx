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

function ConvertSelectInner<T extends PkcsFormat>(
	{
		converter,
		getInputs,
		setInputs,
		value,
		onChange,
		...props
	}: ConvertSelectProps<T, PkcsEncodingProps>,

	_: ForwardedRef<ConvertRef>
) {
	const [pkcsFormat, setPkcsFormat] = useState<T>(props.defaultValue);
	const [messageApi, contextHolder] = message.useMessage({
		maxCount: 1,
	});

	const selectEncoding = async (val: T) => {
		const { privateKey, publicKey, encoding, ...params } = getInputs();
		const { pkcs: fromPkcs, format: fromFormat } =
			PkcsFormats[pkcsFormat as PkcsFormat];
		const { pkcs: toPkcs, format: toFormat } = PkcsFormats[val];
		const fromPkcsEncoding = new PkcsEncodingProps(fromPkcs, fromFormat);
		const toPkcsEncoding = new PkcsEncodingProps(toPkcs, toFormat);
		try {
			const output = await converter.convert(
				privateKey as string,
				publicKey as string,
				fromPkcsEncoding.setEncoding(encoding as TextEncoding),
				toPkcsEncoding.setEncoding(encoding as TextEncoding),
				params
			);
			setInputs({ privateKey: output[0], publicKey: output[1] });
			setPkcsFormat(val);

			onChange?.(val);
		} catch (err) {
			messageApi.warning(err as string);
			error(err as string);
		}
	};

	return (
		<>
			{contextHolder}
			<Select
				onChange={selectEncoding}
				value={value || pkcsFormat}
				{...props}
			/>
		</>
	);
}

export const PkcsFormatSelect = forwardRef(ConvertSelectInner) as <
	T extends PkcsFormat,
	E,
>(
	props: ConvertSelectProps<T, E> & { ref?: React.ForwardedRef<ConvertRef> }
) => ReturnType<typeof ConvertSelectInner>;
