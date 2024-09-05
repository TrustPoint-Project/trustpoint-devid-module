"""This module contains decorators."""

from __future__ import annotations

import click
from typing import TYPE_CHECKING

from trustpoint_devid_module.exceptions import DevIdModuleError, UnexpectedDevIdModuleError

if TYPE_CHECKING:
    from typing import Any


def handle_unexpected_errors(message: str) -> callable:
    """Outer decorator function that requires a message to be included in the UnexpectedDevIdModuleError.

    Args:
        message: The message to be included in the UnexpectedDevIdModuleError.

    Returns:
        callable: The decorator function.
    """
    def handle_unexpected_error_decorator_function(original_function: callable) -> callable:
        """Inner decorator function that takes the decorated function or method.

        Args:
            original_function: The decorated function or method.

        Returns:
            callable: The unexpected error handler function.
        """
        def unexpected_error_handler(*args: Any, **kwargs: Any) -> Any:
            """Handles any unexpected errors and re-raises all other DevIdModuleErrors.

            Args:
                *args: Any positional arguments passed to the original function.
                **kwargs: Any keyword arguments passed to the original function.

            Returns:
                Any: The return value of the original function.
            """
            try:
                result = original_function(*args, **kwargs)
            except DevIdModuleError:
                raise
            except Exception as exception:
                raise UnexpectedDevIdModuleError(message=message, exception=exception) from exception
            return result

        return unexpected_error_handler

    return handle_unexpected_error_decorator_function


def handle_cli_error(original_function: callable) -> callable:
    """Inner decorator function that takes the decorated function or method.

    Args:
        original_function: The decorated function or method.

    Returns:
        callable: The unexpected error handler function.
    """
    def devid_error_handler(*args: Any, **kwargs: Any) -> Any:
        """Handles any unexpected errors and re-raises all other DevIdModuleErrors.

        Args:
            *args: Any positional arguments passed to the original function.
            **kwargs: Any keyword arguments passed to the original function.

        Returns:
            Any: The return value of the original function.
        """
        try:
            result = original_function(*args, **kwargs)
        except DevIdModuleError as exception:
            click.echo(exception)
            return None

        return result

    return devid_error_handler
