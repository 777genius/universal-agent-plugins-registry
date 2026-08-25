"""Deterministic observer test capability classification."""

from __future__ import annotations

import unittest
from collections.abc import Callable, Iterator
from typing import TypeVar


_DISPOSABLE_HOST_ATTRIBUTE = "_requires_disposable_observer_host"
_T = TypeVar("_T", bound=Callable[..., object] | type)


def requires_disposable_observer_host(test: _T) -> _T:
    """Mark a test or test case as requiring the privileged observer host gate."""
    setattr(test, _DISPOSABLE_HOST_ATTRIBUTE, True)
    return test


def _test_cases(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _test_cases(test)
        else:
            assert isinstance(test, unittest.TestCase)
            yield test


def _requires_disposable_host(test: unittest.TestCase) -> bool:
    method = getattr(test, test._testMethodName)
    return bool(
        getattr(type(test), _DISPOSABLE_HOST_ATTRIBUTE, False)
        or getattr(method, _DISPOSABLE_HOST_ATTRIBUTE, False)
    )


def load_partition(*, privileged: bool) -> unittest.TestSuite:
    """Load exactly one side of the portable/disposable-host partition."""
    from observer.tests import test_observer_service

    discovered = unittest.defaultTestLoader.loadTestsFromModule(test_observer_service)
    selected = (
        test for test in _test_cases(discovered)
        if _requires_disposable_host(test) is privileged
    )
    return unittest.TestSuite(selected)
