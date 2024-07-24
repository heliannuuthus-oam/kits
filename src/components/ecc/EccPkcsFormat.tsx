import { forwardRef } from "react";
import {
	ConvertRef,
	ConvertSelectProps,
	EccFromat,
	Pkcs8Format,
	PkcsEncodingProps,
	Sec1Format,
	eccPkcsConverter,
} from "../converter/converter";
import { PkcsFormatSelect } from "../converter/PkcsFormatSelect";

export const EccPkcsSelect = forwardRef<
	ConvertRef,
	ConvertSelectProps<EccFromat, PkcsEncodingProps>
>(
	(
		{
			converter = eccPkcsConverter,
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
					{ value: Sec1Format.SEC1_PEM, label: <span>sec1-pem</span> },
					{ value: Sec1Format.SEC1_DER, label: <span>sec1-der</span> },
				]}
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

export const EccPkcsFormat = () => {
	const form = useFormInstance();

	return (
		<Form.Item noStyle name={["elliptic_curve", "pkcsFormat"]}>
			<EccPkcsSelect
				converter={eccPkcsConverter}
				style={{
					minWidth: derviceKeyConfigButtonWidth,
					minHeight: derviceKeyConfigButtonHeight,
				}}
				getInputs={() => form.getFieldValue("elliptic_curve")}
				setInputs={(elliptic_curve) => {
					form.setFieldsValue({ elliptic_curve });
				}}
			/>
		</Form.Item>
	);
};
