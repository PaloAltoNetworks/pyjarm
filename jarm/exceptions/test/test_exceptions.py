import pytest
from exceptions.exceptions import (
    PyJARMException,
    PyJARMUnsupportValueException,
    PyJARMUnexpectedException,
    PyJARMInvalidTarget,
    PyJARMInvalidProxy,
    PyJARMProxyError
)

class TestPyJARMExceptions:

    def test_pyjarm_exception_inheritance(self):
        assert issubclass(PyJARMException, Exception)

    def test_pyjarm_unsupport_value_exception_inheritance(self):
        assert issubclass(PyJARMUnsupportValueException, PyJARMException)

    def test_pyjarm_unexpected_exception_inheritance(self):
        assert issubclass(PyJARMUnexpectedException, PyJARMException)

    def test_pyjarm_invalid_target_inheritance(self):
        assert issubclass(PyJARMInvalidTarget, PyJARMException)

    def test_pyjarm_invalid_proxy_inheritance(self):
        assert issubclass(PyJARMInvalidProxy, PyJARMException)

    def test_pyjarm_proxy_error_inheritance(self):
        assert issubclass(PyJARMProxyError, PyJARMException)

    def test_pyjarm_exception_instantiation(self):
        with pytest.raises(PyJARMException):
            raise PyJARMException("Test exception")

    def test_pyjarm_unsupport_value_exception_instantiation(self):
        with pytest.raises(PyJARMUnsupportValueException):
            raise PyJARMUnsupportValueException("Unsupported value")

    def test_pyjarm_unexpected_exception_instantiation(self):
        with pytest.raises(PyJARMUnexpectedException):
            raise PyJARMUnexpectedException("Unexpected error")

    def test_pyjarm_invalid_target_instantiation(self):
        with pytest.raises(PyJARMInvalidTarget):
            raise PyJARMInvalidTarget("Invalid target")

    def test_pyjarm_invalid_proxy_instantiation(self):
        with pytest.raises(PyJARMInvalidProxy):
            raise PyJARMInvalidProxy("Invalid proxy")

    def test_pyjarm_proxy_error_instantiation(self):
        with pytest.raises(PyJARMProxyError):
            raise PyJARMProxyError("Proxy error")

    def test_exception_message_preservation(self):
        error_message = "Test error message"
        with pytest.raises(PyJARMException) as exc_info:
            raise PyJARMException(error_message)
        assert str(exc_info.value) == error_message

    def test_exception_chaining(self):
        original_error = ValueError("Original error")
        try:
            raise original_error
        except ValueError as e:
            with pytest.raises(PyJARMException) as exc_info:
                raise PyJARMException("Chained exception") from e
        
        assert exc_info.value.__cause__ == original_error

    def test_multiple_exception_handling(self):
        exceptions = [
            PyJARMUnsupportValueException,
            PyJARMUnexpectedException,
            PyJARMInvalidTarget,
            PyJARMInvalidProxy,
            PyJARMProxyError
        ]
        
        for exception_class in exceptions:
            with pytest.raises(exception_class):
                raise exception_class(f"Testing {exception_class.__name__}")

    def test_exception_type_checking(self):
        try:
            raise PyJARMUnsupportValueException("Unsupported value")
        except PyJARMException as e:
            assert isinstance(e, PyJARMUnsupportValueException)
            assert isinstance(e, PyJARMException)
            assert not isinstance(e, PyJARMUnexpectedException)

    def test_custom_attributes(self):
        class CustomPyJARMException(PyJARMException):
            def __init__(self, message, error_code):
                super().__init__(message)
                self.error_code = error_code

        custom_exception = CustomPyJARMException("Custom error", 500)
        assert custom_exception.error_code == 500
        assert str(custom_exception) == "Custom error"

    def test_exception_in_context_manager(self):
        class ExceptionRaiser:
            def __enter__(self):
                return self
            
            def __exit__(self, exc_type, exc_value, traceback):
                if exc_type is PyJARMException:
                    return True
                return False

        with ExceptionRaiser():
            raise PyJARMException("This should be caught")

        with pytest.raises(ValueError):
            with ExceptionRaiser():
                raise ValueError("This should not be caught")
