import { Select, message } from "antd";
import { forwardRef, useState } from "react";
import {
	ConvertRef,
	PkcsFormat,
	PkcsFormats,
	PkcsEncodingProps,
} from "./converter";
import { ConvertSelectProps } from "./converter";
import { TextEncoding } from "../codec/codec";

function ConvertSelectInner<T extends PkcsFormat>({
	converter,
	getInputs,
	setInputs,
	value,
	onChange,
	...props
}: ConvertSelectProps<T, PkcsEncodingProps>) {
	const [pkcsFormat, setPkcsFormat] = useState<T>(props.defaultValue);
	const [messageApi, contextHolder] = message.useMessage({
		maxCount: 1,
	});

	const selectEncoding = async (val: T) => {
		const { privateKey, publicKey, encoding } = getInputs();

		const fromPkcs = PkcsFormats[pkcsFormat];
		const toPkcs = PkcsFormats[val];

		try {
			const output = await converter.convert(
				privateKey as string,
				publicKey as string,
				fromPkcs.setEncoding(encoding as TextEncoding),
				toPkcs.setEncoding(encoding as TextEncoding)
			);

			setInputs({ privateKey: output[0], publicKey: output[1] });
			setPkcsFormat(val);
			onChange?.(val);
		} catch (err) {
			messageApi.warning("error: " + err);
			console.log(err);
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
