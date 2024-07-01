import { Form, Select, SelectProps, Space } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import { useEffect, useState } from "react";
import { fetchDigests } from "../../api/constants";
import { fetchRsaEncryptionPadding } from "../../api/rsa";
import { RsaEncryptionForm } from "../../pages/encryption/rsa";

export const RsaPadding = () => {
	const form = useFormInstance<RsaEncryptionForm>();

	const [digests, setDigests] = useState<SelectProps["options"]>([]);
	const [mgfdigests, setMgfDigests] = useState<SelectProps["options"]>([]);

	const [paddings, setPaddings] = useState<SelectProps["options"]>([]);
	const padding = Form.useWatch("padding", form);

	useEffect(() => {
		fetchRsaEncryptionPadding().then((pads) => {
			const paddingValue = pads.map((pad) => ({ label: pad, value: pad }));
			setPaddings(paddingValue);
			form.setFieldsValue({ padding: pads[1] });
		});
		fetchDigests().then((digs) => {
			const digValues = digs.map((dig) => ({ label: dig, value: dig }));
			setDigests(digValues);
			setMgfDigests(digValues);
			form.setFieldsValue({ digest: digs[1], mgfDigest: digs[1] });
		});
	}, [setDigests, setMgfDigests, setPaddings]);

	return (
		<Space.Compact style={{ width: "100%" }}>
			<Form.Item
				style={{ width: padding == "oaep" ? "100%" : "33.3%" }}
				name="padding"
				children={<Select options={paddings} />}
			/>
			{[
				<Form.Item
					style={{ width: "100%" }}
					name="digest"
					children={<Select options={digests} />}
				/>,
				<Form.Item
					style={{ width: "100%" }}
					name="mgfDigest"
					children={<Select options={mgfdigests} />}
				/>,
			]
				.filter((_) => padding == "oaep")
				.map((c) => c)}
		</Space.Compact>
	);
};
