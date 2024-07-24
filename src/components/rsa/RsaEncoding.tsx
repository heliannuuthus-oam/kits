import { forwardRef } from "react";
import { TextEncoding, textEncodings } from "../codec/codec";
import {
	ConvertRef,
	ConvertSelectProps,
	PkcsEncodingProps,
	rsaEncodingConverter,
} from "../converter/converter";
import { PkcsEncodingSelect } from "../converter/PkcsEncodingSelect";

import { Form } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

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

export const RsaEncoding = () => {
	const form = useFormInstance();

	return (
		<Form.Item noStyle name={["rsa", "encoding"]}>
			<RsaEncodingSelect
				converter={rsaEncodingConverter}
				getInputs={() => form.getFieldValue("rsa")}
				setInputs={(value) => {
					form.setFieldsValue({ rsa: value });
				}}
				style={{
					minWidth: derviceKeyConfigButtonWidth,
					minHeight: derviceKeyConfigButtonHeight,
				}}
			/>
		</Form.Item>
	);
};
