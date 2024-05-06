import { writeText } from "@tauri-apps/api/clipboard";
import {
	Button,
	Col,
	Form,
	Input,
	Row,
	Space,
	Typography,
	message,
} from "antd";
import { AesForm } from "../../pages/encryption/aes";
const { Title } = Typography;
const { TextArea } = Input;

export type AesOutputRef = {
	setOutput: (output: Uint8Array) => void;
};

export type AesOutputProps = {};

const size = "middle";

const AesOutput = () => {
	const form = Form.useFormInstance<AesForm>();

	const [msgApi, msgContextHolder] = message.useMessage();

	const copy = async () => {
		await writeText(form.getFieldValue("output"));
		msgApi.success("copied");
	};

	return (
		<Space
			direction="vertical"
			size="middle"
			style={{ display: "flex", width: "100%", padding: "0 24px" }}
		>
			{msgContextHolder}
			<Row justify="space-between" align="middle">
				<Col>
					<Title style={{ margin: 0 }} level={5}>
						Output:
					</Title>
				</Col>
				<Col>
					<Button size={size} onClick={copy}>
						copy
					</Button>
				</Col>
			</Row>
			<Form.Item noStyle name="output">
				<TextArea
					style={{ width: "100%" }}
					autoSize={{ minRows: 29, maxRows: 29 }}
				/>
			</Form.Item>
		</Space>
	);
};
export default AesOutput;
