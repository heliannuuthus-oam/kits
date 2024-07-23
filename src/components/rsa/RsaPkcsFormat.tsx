import { Form, FormInstance } from "antd";
import { forwardRef } from "react";
import { RsaKeyDeriveForm } from ".";
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

export const RsaPkcsFormat = ({
	form,
}: {
	form: FormInstance<RsaKeyDeriveForm>;
}) => {
	return (
		<Form form={form}>
			<Form.Item name="pkcsFormat" noStyle>
				<RsaPkcsSelect
					converter={rsaPkcsConverter}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
					getInputs={() =>
						form.getFieldsValue(["privateKey", "publicKey", "encoding"])
					}
					setInputs={(value) => {
						form.setFieldsValue(value);
					}}
				/>
			</Form.Item>
		</Form>
	);
};
