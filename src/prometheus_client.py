# Stub for prometheus_client

def generate_latest(registry):
    # Return minimal metric data for tests
    return b"http_requests_total 0\n"

CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

class CollectorRegistry:
    def __init__(self):
        pass
    def register(self, collector):
        pass

class Counter:
    def __init__(self, name, description, labelnames=None):
        pass
    def labels(self, **kwargs):
        return self
    def inc(self):
        pass 