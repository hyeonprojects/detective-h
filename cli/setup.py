from setuptools import setup, find_packages

setup(
    name="virus_tracker",
    version="0.1.0",
    description="바이러스 추적 및 분석 도구",
    author="Detective-H",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'virus-tracker=virus_tracker.__main__:main',
        ],
    },
    python_requires='>=3.6',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
