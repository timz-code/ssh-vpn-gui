from setuptools import find_packages, setup


setup(
    name="ssh-vpn-gui",
    version="0.2.13",
    description="Ubuntu GTK GUI for SSH -w TUN VPN routing with local DNS and nftables",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.10",
    package_dir={"": "src"},
    packages=find_packages("src"),
    install_requires=[
        "maxminddb>=2.6",
        "pexpect>=4.9",
        "PyGObject>=3.42",
    ],
    entry_points={
        "console_scripts": [
            "ssh-vpn-gui=ssh_vpn_gui.app:main",
            "ssh-vpn-helper=ssh_vpn_gui.helper:main",
        ],
    },
)
