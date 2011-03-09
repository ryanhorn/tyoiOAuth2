from setuptools import setup

setup(
    name="tyoi.OAuth2",
    version="0.1.0",
    author="Ryan Horn",
    author_email="ryan.horn.web@gmail.com",
    description=("Implements the client side of the OAuth 2 protocol"),
    keywords="oauth oauth2 auth authentication",
    url="https://github.com/ryanhorn/tyoiOAuth2",
    packages=["tyoi", "tyoi.oauth2"],
    test_suite="tests",
    tests_require=["mox"]
)
