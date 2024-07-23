import "./App.css";

import { Flex, Layout } from "antd";
import React, { useState } from "react";
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

const App: React.FC = () => {
	const [siderWidth, setSiderWidth] = useState<string | number>("25%");

	return (
		<Flex>
			<Layout hasSider>
				<Sider
					breakpoint="lg"
					collapsedWidth="0"
					trigger={null}
					onCollapse={(collapsed, _) => {
						setSiderWidth(collapsed ? 0 : "25%");
					}}
					style={siderStyle}
					width={siderWidth}
				/>
				<Layout>
					<Content
						style={{
							marginLeft: siderWidth,
							height: "100%",
							backgroundColor: "#fff",
						}}
					/>
				</Layout>
			</Layout>
		</Flex>
	);
};

export default App;
