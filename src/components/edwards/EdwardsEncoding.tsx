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

import { Form } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

export const EdwardsEncoding = () => {
	const form = useFormInstance();

	return (
		<Form.Item noStyle name={["edwards", "encoding"]}>
			<EdwardsEncodingSelect
				converter={edwardsEncodingConverter}
				getInputs={() => form.getFieldValue("edwards")}
				setInputs={(edwards) => {
					form.setFieldsValue({ edwards });
				}}
				style={{
					minWidth: derviceKeyConfigButtonWidth,
					minHeight: derviceKeyConfigButtonHeight,
				}}
			/>
		</Form.Item>
	);
};
