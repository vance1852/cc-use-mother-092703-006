"""环境事件响应服务向 API 和 CLI 暴露的稳定错误。"""


class EnvironmentalError(RuntimeError):
    code = "environmental_error"
    status = 400


class NotFound(EnvironmentalError):
    code = "not_found"
    status = 404


class Conflict(EnvironmentalError):
    code = "conflict"
    status = 409


class Forbidden(EnvironmentalError):
    code = "forbidden"
    status = 403


class InvalidState(EnvironmentalError):
    code = "invalid_state"
    status = 409


class ValidationFailed(EnvironmentalError):
    code = "validation_failed"
    status = 422
