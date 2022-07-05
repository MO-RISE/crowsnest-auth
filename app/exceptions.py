class APIException(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class VerifyException(Exception):
    def __init__(self, message: str):
        self.message = message
