#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""TODO"""

import pytest


def pytest_addoption(parser):
    """TODO"""
    parser.addoption(
        "--env", action="store",
        default="test",
        help="my option: test/gitlab"
    )


def pytest_configure(config):
    """TODO"""
    config.addinivalue_line(
        "markers",
        "run_test_if_env(env): this mark run the tests for the given env"
    )


def pytest_runtest_setup(item):
    """TODO"""
    env_names = [mark.args[0] for mark in item.iter_markers(
        name="run_test_if_env")]
    if env_names:
        if not item.config.getoption("--env") in env_names:
            # pylint: disable=consider-using-f-string
            pytest.skip(
                    "Test skipped because env is not {!r}".format(env_names))
