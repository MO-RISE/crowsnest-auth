"""
Exceptions
"""


class APIException(Exception):
    """Custom API Exception"""

    def __init__(self, status_code: int, message: str):
        super().__init__()
        self.status_code = status_code
        self.message = message


class VerifyException(Exception):
    """Custom Verify Exception"""

    def __init__(self, message: str):
        super().__init__()
        self.message = message
