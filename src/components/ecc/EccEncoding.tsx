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

import { Form, FormInstance } from "antd";
import { EccKeyDeriveForm } from ".";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

export const EccEncoding = ({
	form,
}: {
	form: FormInstance<EccKeyDeriveForm>;
}) => {
	return (
		<Form form={form}>
			<Form.Item noStyle name="encoding">
				<EccEncodingSelect
					converter={eccEncodingConverter}
					getInputs={() =>
						form.getFieldsValue([
							"privateKey",
							"publicKey",
							"pkcsFormat",
							"curveName",
						])
					}
					setInputs={(value) => {
						form.setFieldsValue(value);
					}}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
				/>
			</Form.Item>
		</Form>
	);
};
