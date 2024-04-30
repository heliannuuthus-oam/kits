import { ConfigProvider, Layout, Menu, MenuProps, SiderProps } from "antd";
import { useEffect, useState } from "react";
import { Link, RouteObject, useLocation } from "react-router-dom";
import routes from "virtual:generated-pages-react";

const { Sider: AntdSider } = Layout;

type MenuItem = Required<MenuProps>["items"][number];

function Item(
	label: React.ReactNode,
	key: React.Key,
	icon?: React.ReactNode,
	children?: MenuItem[],
	type?: "group"
): MenuItem {
	return {
		key,
		icon,
		children,
		label,
		type,
	} as MenuItem;
}

const chidren = (ros: RouteObject[], parent: string | undefined) => {
	return ros
		.filter((ro) => ro.path !== "")
		.map((ro: RouteObject) => {
			return Item(
				<Link to={parent + "/" + ro.path}>{ro.path}</Link>,
				parent + "/" + ro.path || 2
			);
		});
};

const menuItems: MenuProps["items"] = routes
	.filter((ro) => ro.path !== "/")
	.map((ro: RouteObject) => {
		return Item(
			<Link to={ro.path || "/"}>{ro.path}</Link>,
			ro.path || 1,
			null,
			ro.children ? chidren(ro.children, ro.path) : []
		);
	});

export const Sider = ({ ...props }: SiderProps) => {
	const [selectedKeys, setSelectedKeys] = useState<string[]>([]);
	const [openKeys, setOpenKeys] = useState<string[]>([]);
	const { pathname } = useLocation();
	useEffect(() => {
		const leaf = pathname.lastIndexOf("/");
		const parent = pathname.substring(
			1,
			leaf === -1 || leaf === 0 ? pathname.length : leaf
		);
		setOpenKeys([parent]);
		setSelectedKeys([location.pathname.substring(1)]);
	}, [pathname]);

	const onChange = ({ keyPath }: { keyPath: string[] }) => {
		setOpenKeys([keyPath[-1]]);
		setSelectedKeys([keyPath[-2]]);
	};

	return (
		<ConfigProvider
			theme={{
				token: {
					colorLink: "#000",
					colorPrimaryActive: "#000",
				},
				components: {
					Menu: {
						itemActiveBg: "rgba(0, 0, 0, 0.06)",
						itemSelectedBg: "rgba(0, 0, 0, 0.06)",
					},
				},
			}}
		>
			<AntdSider {...props}>
				<Menu
					mode="inline"
					style={{ width: 256, height: "100%" }}
					selectedKeys={selectedKeys}
					openKeys={openKeys}
					items={menuItems}
					onClick={onChange}
				/>
			</AntdSider>
		</ConfigProvider>
	);
};
