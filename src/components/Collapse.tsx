import { CaretRightOutlined } from "@ant-design/icons";
import { Collapse as AntdCollapse, CollapseProps, ConfigProvider } from "antd";
import { createStyles } from "antd-style";

const useStyles = createStyles(({ css }) => ({
	container: css`
		.ant-collapse-content-box {
			padding-left: 0;
		}
	`,
}));
const Collapse = ({ ...props }: CollapseProps) => {
	const { styles } = useStyles();
	return (
		<ConfigProvider
			theme={{
				components: {
					Collapse: {
						padding: 0,
					},
				},
			}}
		>
			<AntdCollapse
				className={styles.container}
				{...props}
				ghost
				expandIcon={({ isActive }) => (
					<CaretRightOutlined rotate={isActive ? 90 : 0} />
				)}
			/>
		</ConfigProvider>
	);
};

export default Collapse;
