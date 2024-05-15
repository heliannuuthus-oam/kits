import { forwardRef } from "react";
import {
	ConvertRef,
	ConvertSelectProps,
	PkcsEncodingProps,
	eccEncodingConverter,
} from "../converter/converter";
import { PkcsEncodingSelect } from "../converter/PkcsEncodingSelect";
import { TextEncoding, textEncodings } from "../codec/codec";

export const EccEncodingSelect = forwardRef<
	ConvertRef,
	ConvertSelectProps<TextEncoding, PkcsEncodingProps>
>(({ onChange, value, converter = eccEncodingConverter, ...props }, ref) => {
	return (
		<PkcsEncodingSelect
			ref={ref}
			converter={converter}
			value={value}
			onChange={onChange}
			defaultValue={TextEncoding.UTF8}
			options={textEncodings}
			{...props}
		/>
	);
});
