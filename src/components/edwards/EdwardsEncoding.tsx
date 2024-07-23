import { forwardRef } from "react";
import { TextEncoding, textEncodings } from "../codec/codec";
import {
	ConvertRef,
	ConvertSelectProps,
	PkcsEncodingProps,
	edwardsEncodingConverter,
} from "../converter/converter";
import { PkcsEncodingSelect } from "../converter/PkcsEncodingSelect";

export const EdwardsEncodingSelect = forwardRef<
	ConvertRef,
	ConvertSelectProps<TextEncoding, PkcsEncodingProps>
>(
	(
		{ onChange, value, converter = edwardsEncodingConverter, ...props },
		ref
	) => {
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
	}
);

import { Form, FormInstance } from "antd";
import { EdwardsDeriveKeyForm } from ".";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

export const EdwardsEncoding = ({
	form,
}: {
	form: FormInstance<EdwardsDeriveKeyForm>;
}) => {
	return (
		<Form form={form}>
			<Form.Item noStyle name="encoding">
				<EdwardsEncodingSelect
					converter={edwardsEncodingConverter}
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
