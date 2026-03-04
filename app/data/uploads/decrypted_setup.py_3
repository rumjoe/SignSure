from setuptools import setup, find_packages

setup(
    name="signsure",
    version="1.0.0",
    description="Open-Source PKI Document Signing & Verification System",
    author="SignSure Contributors",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=42.0.0",
        "flask>=3.0.0",
        "werkzeug>=3.0.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "signsure=run:main",
        ],
    },
)
