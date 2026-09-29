"""环境事件响应服务向 API 和 CLI 暴露的稳定错误。"""


class ResponseError(RuntimeError):
    code = "response_error"
    status = 400


class NotFound(ResponseError):
    code = "not_found"
    status = 404


class Conflict(ResponseError):
    code = "conflict"
    status = 409


class Forbidden(ResponseError):
    code = "forbidden"
    status = 403


class InvalidState(ResponseError):
    code = "invalid_state"
    status = 409


class ValidationFailed(ResponseError):
    code = "validation_failed"
    status = 422
