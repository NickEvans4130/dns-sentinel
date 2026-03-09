from setuptools import setup, find_packages

setup(
    name="dns-sentinel",
    version="0.1.0",
    description="Privacy-aware DNS blocker with Discord alerts",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "dnslib>=0.9.23",
        "requests>=2.31.0",
        "tomli>=2.0.1; python_version < '3.11'",
        "schedule>=1.2.0",
    ],
    entry_points={
        "console_scripts": [
            "dns-sentinel=dns_sentinel.server:main",
            "dns-sentinel-report=dns_sentinel.reporter:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Internet :: Name Service (DNS)",
    ],
)
