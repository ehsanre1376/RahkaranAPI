from setuptools import setup, find_packages

setup(
    name="RahkaranAPI",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
                "requests>=2.26.0",
        "rsa>=4.7.2",
    ],
    author="Ehsan REZAEI",
    author_email="ehsanre@systemgroup.net",
    description="Rahkaran Authentication Client",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ehsanre1376/RahkaranAPI",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)