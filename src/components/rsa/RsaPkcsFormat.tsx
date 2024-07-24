import { Form } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import { forwardRef } from "react";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";
import {
	ConvertRef,
	ConvertSelectProps,
	Pkcs1Format,
	Pkcs8Format,
	PkcsEncodingProps,
	RsaFormat,
	rsaPkcsConverter,
} from "../converter/converter";
import { PkcsFormatSelect } from "../converter/PkcsFormatSelect";

export const RsaPkcsSelect = forwardRef<
	ConvertRef,
	ConvertSelectProps<RsaFormat, PkcsEncodingProps>
>(
	(
		{
			converter = rsaPkcsConverter,
			getInputs,
			setInputs,
			onChange,
			value,
			...props
		},
		ref
	) => {
		return (
			<PkcsFormatSelect
				ref={ref}
				converter={converter}
				getInputs={getInputs}
				setInputs={setInputs}
				value={value}
				onChange={onChange}
				defaultValue={Pkcs8Format.PKCS8_PEM}
				options={[
					{ value: Pkcs8Format.PKCS8_PEM, label: <span>pkcs8-pem</span> },
					{ value: Pkcs8Format.PKCS8_DER, label: <span>pkcs8-der</span> },
					{ value: Pkcs1Format.PKCS1_PEM, label: <span>pkcs1-pem</span> },
					{ value: Pkcs1Format.PKCS1_DER, label: <span>pkcs1-der</span> },
				]}
				{...props}
			/>
		);
	}
);

export const RsaPkcsFormat = () => {
	const form = useFormInstance();
	return (
		<Form.Item name={["rsa", "pkcsFormat"]} noStyle>
			<RsaPkcsSelect
				converter={rsaPkcsConverter}
				style={{
					minWidth: derviceKeyConfigButtonWidth,
					minHeight: derviceKeyConfigButtonHeight,
				}}
				getInputs={() => form.getFieldValue("rsa")}
				setInputs={(rsa) => {
					form.setFieldsValue({ rsa });
				}}
			/>
		</Form.Item>
	);
};
