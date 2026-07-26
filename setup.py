from setuptools import setup, find_packages

setup(
    name="foresightops",
    version="1.0.0",
    description="CI/CD Blast Radius Analyzer — Automated Remediation Before Vulnerability Reaches Code",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="DD Bala",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "requests>=2.31.0",
        "PyYAML>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "foresightops=foresightops.cli:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security cicd github-actions supply-chain blast-radius devops",
)
