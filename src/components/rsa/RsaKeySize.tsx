import { Form, FormInstance, Select, SelectProps } from "antd";
import { useEffect, useState } from "react";
import { RsaKeyDeriveForm } from ".";
import { fetchRsaKeySize } from "../../api/rsa";

export const RsaKeySize = ({
	form,
}: {
	form: FormInstance<RsaKeyDeriveForm>;
}) => {
	const [keySizes, setKeySizes] = useState<SelectProps["options"]>();

	useEffect(() => {
		fetchRsaKeySize().then((keySizes) => {
			form.setFieldsValue({ keySize: keySizes[0] });
			setKeySizes(
				keySizes.map((keySize) => {
					return {
						value: keySize,
						label: keySize,
					};
				})
			);
		});
	}, [fetchRsaKeySize]);

	return (
		<Form form={form}>
			<Form.Item noStyle name="keySize">
				<Select options={keySizes} style={{ minWidth: 120 }} />
			</Form.Item>
		</Form>
	);
};
