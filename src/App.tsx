import "./App.css";

import React from "react";
import { Layout, Flex } from "antd";
import { Sider } from "./components/Sider";
import { Content } from "./components/Content";

const { Header } = Layout;

const headerStyle: React.CSSProperties = {
	textAlign: "center",
	height: 64,
	paddingInline: 48,
	lineHeight: "64px",
	backgroundColor: "#fff",
};

const contentStyle: React.CSSProperties = {
	textAlign: "center",
	minHeight: 520,
	maxHeight: "100vh",
	backgroundColor: "#fff",
};

const siderStyle: React.CSSProperties = {
	textAlign: "center",
	lineHeight: "120px",
	backgroundColor: "#fff",
};

const layoutStyle = {
	overflow: "hidden",
};

const App: React.FC = () => (
	<Flex>
		<Layout style={layoutStyle}>
			<Sider
				breakpoint="lg"
				collapsedWidth="0"
				onBreakpoint={(broken) => {
					console.log(broken);
				}}
				trigger={null}
				onCollapse={(collapsed, type) => {
					console.log(collapsed, type);
				}}
				style={siderStyle}
				width="25%"
			/>
			<Layout>
				<Header style={headerStyle}>Header</Header>
				<Content style={contentStyle} />
			</Layout>
		</Layout>
	</Flex>
);

export default App;
