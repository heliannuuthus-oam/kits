import { forwardRef } from "react";
import { TextEncoding, textEncodings } from "../codec/codec";
import {
	ConvertRef,
	ConvertSelectProps,
	PkcsEncodingProps,
	rsaEncodingConverter,
} from "../converter/converter";
import { PkcsEncodingSelect } from "../converter/PkcsEncodingSelect";

import { Form, FormInstance } from "antd";
import { RsaKeyDeriveForm } from ".";
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

export const RsaEncoding = ({
	form,
}: {
	form: FormInstance<RsaKeyDeriveForm>;
}) => {
	return (
		<Form form={form}>
			<Form.Item noStyle name="encoding">
				<RsaEncodingSelect
					converter={rsaEncodingConverter}
					getInputs={() =>
						form.getFieldsValue(["privateKey", "publicKey", "pkcsFormat"])
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
