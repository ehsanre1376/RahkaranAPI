from setuptools import setup, find_packages

setup(
    name="rahkaran_auth",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.26.0",
        "rsa>=4.7.2"
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="Rahkaran Authentication Client",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/rahkaran-auth",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)