from setuptools import setup, find_packages

setup(
    name="pcapstats",
    version="0.0.1",
    packages=find_packages(),
    license="Apache License 2.0",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    include_package_data=True,
    author="Sanaa Khelloqi",
    author_email="sanaa.khelloqi@stud-mail.uni-wuerzburg",
    url="https://github.com/sanaakhelloqi/pcapstats",
    entry_points={
        'console_scripts': [
            'pcapstats-stats=cli.stats:stats',
            'pcapstats-compare=cli.compare:compare'
            ],
    },
    python_requires='>=3.6',
    install_requires=[
        "scapy",
        "numpy",
        "scipy",
        "pandas",
        "click"
    ],
    keywords=['pcap', 'network', 'network traffic']
)