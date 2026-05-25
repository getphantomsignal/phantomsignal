from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#") and not line.startswith("# ──")
    ]

setup(
    name="nightowl-osint",
    version="1.0.0",
    description="NightOwl :: Open-Source OSINT Intelligence Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="packetsn1ffer",
    url="https://github.com/the-clipper/nightowl",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "nightowl=nightowl.cli:main",
            "owl=nightowl.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords="osint intelligence reconnaissance security pentest",
    project_urls={
        "Bug Reports": "https://github.com/the-clipper/nightowl/issues",
        "Source": "https://github.com/the-clipper/nightowl",
    },
)
