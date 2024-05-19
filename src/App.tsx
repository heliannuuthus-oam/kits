import "./App.css";

import { Flex, Layout } from "antd";
import React from "react";
import { Content } from "./components/Content";
import { Sider } from "./components/Sider";

const siderStyle: React.CSSProperties = {
	textAlign: "center",
	lineHeight: "120px",
	backgroundColor: "#fff",
	overflow: "auto",
	height: "100vh",
	position: "fixed",
	left: 0,
	top: 0,
	bottom: 0,
};

const App: React.FC = () => (
	<Flex>
		<Layout hasSider>
			<Sider
				breakpoint="lg"
				collapsedWidth="0"
				trigger={null}
				onCollapse={(collapsed, type) => {
					console.log(collapsed, type);
				}}
				style={siderStyle}
				width="25%"
			/>
			<Layout>
				<Content style={{ marginLeft: "25%", height: "100%" }} />
			</Layout>
		</Layout>
	</Flex>
);

export default App;
