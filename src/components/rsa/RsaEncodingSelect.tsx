import { forwardRef } from "react";
import {
	ConvertRef,
	ConvertSelectProps,
	PkcsEncodingProps,
	rsaEncodingConverter,
} from "../converter/converter";
import { PkcsEncodingSelect } from "../converter/PkcsEncodingSelect";
import { TextEncoding, textEncodings } from "../codec/codec";

export const RsaEncodingSelect = forwardRef<
	ConvertRef,
	ConvertSelectProps<TextEncoding, PkcsEncodingProps>
>(
	(
		{
			converter = rsaEncodingConverter,
			getInputs,
			setInputs,
			onChange,
			value,
			...props
		},
		ref
	) => {
		return (
			<PkcsEncodingSelect
				ref={ref}
				converter={converter}
				getInputs={getInputs}
				setInputs={setInputs}
				value={value}
				onChange={onChange}
				defaultValue={TextEncoding.UTF8}
				options={textEncodings}
				{...props}
			/>
		);
	}
);
