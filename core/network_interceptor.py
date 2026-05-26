from PySide6.QtCore import QObject, Signal
from PySide6.QtWebEngineCore import QWebEngineUrlRequestInterceptor


class NetworkEventBus(QObject):
    request_seen = Signal(str, str, str)


class NetworkInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, event_bus: NetworkEventBus):
        super().__init__()
        self.event_bus = event_bus

    def interceptRequest(self, info):
        method = bytes(info.requestMethod()).decode("utf-8", errors="replace")
        url = info.requestUrl().toString()
        resource_type = str(info.resourceType())

        self.event_bus.request_seen.emit(method, url, resource_type)