class PayloadTooLargeError(Exception):
    """Raised when incoming request body exceeds the maximum permitted byte size."""
    def __init__(self, message: str = "Payload too large"):
        self.message = message
        super().__init__(self.message)


__all__ = ["PayloadTooLargeError"]