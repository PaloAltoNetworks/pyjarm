class PyJARMException(Exception):
    pass


class PyJARMUnsupportValueException(PyJARMException):
    pass


class PyJARMUnexpectedException(PyJARMException):
    pass


class PyJARMInvalidTarget(PyJARMException):
    pass
