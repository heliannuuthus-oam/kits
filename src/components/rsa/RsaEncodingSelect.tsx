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
>(({ converter = rsaEncodingConverter, onChange, value, ...props }, ref) => {
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
