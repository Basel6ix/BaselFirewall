from setuptools import setup, find_packages

setup(
    name="baselfirewall",
    version="1.0.0",
    author="Basel Abu-Radaha",
    author_email="your.email@example.com",
    description="A comprehensive personal firewall system",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/BaselFirewall",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Networking :: Firewalls",
    ],
    python_requires=">=3.8",
    install_requires=[
        "bcrypt>=4.0.1",
        "netifaces>=0.11.0",
        "psutil>=5.9.5",
        "tk>=8.6.12",
        "matplotlib>=3.7.1",
        "scapy>=2.5.0",
        "pyshark>=0.6.0",
        "colorama>=0.4.6",
        "rich>=13.3.5",
        "click>=8.1.3",
    ],
    entry_points={
        "console_scripts": [
            "baselfirewall=main:main",
            "baselfirewall-gui=gui.interface:main",
        ],
    },
    include_package_data=True,
    package_data={
        "baselfirewall": [
            "config/*.json",
            "config/*.conf",
        ],
    },
) 