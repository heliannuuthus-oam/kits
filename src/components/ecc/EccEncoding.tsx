import { forwardRef } from "react";
import { TextEncoding, textEncodings } from "../codec/codec";
import {
	ConvertRef,
	ConvertSelectProps,
	PkcsEncodingProps,
	eccEncodingConverter,
} from "../converter/converter";
import { PkcsEncodingSelect } from "../converter/PkcsEncodingSelect";

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

import { Form } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

export const EccEncoding = () => {
	const form = useFormInstance();

	return (
		<Form.Item noStyle name={["elliptic_curve", "encoding"]}>
			<EccEncodingSelect
				converter={eccEncodingConverter}
				getInputs={() => form.getFieldValue("elliptic_curve")}
				setInputs={(elliptic_curve) => {
					form.setFieldsValue({ elliptic_curve });
				}}
				style={{
					minWidth: derviceKeyConfigButtonWidth,
					minHeight: derviceKeyConfigButtonHeight,
				}}
			/>
		</Form.Item>
	);
};
