from setuptools import setup, find_packages

setup(
    name="baselfirewall",
    version="1.0.0",
    author="Basel Abu-Radah",
    description="A Python-based personal firewall for Linux with advanced security features",
    packages=find_packages(),
    install_requires=[
        "bcrypt>=4.0.1",
        "netifaces>=0.11.0",
        "psutil>=5.9.5",
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
        ],
    },
    python_requires=">=3.8",
    include_package_data=True,
    package_data={
        "baselfirewall": ["config/*.json", "config/*.conf"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.8",
        "Topic :: System :: Networking :: Firewalls",
    ],
)
