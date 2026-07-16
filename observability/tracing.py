"""OpenTelemetry tracing setup — spans across API → swarm → sandbox.

Configures a TracerProvider with an OTLP exporter when ``APP_OTEL_ENDPOINT`` is
set; otherwise tracing is a no-op (the :func:`span` context manager yields
``None``). Optional OTel packages are imported lazily so this module is always
importable, even in minimal environments.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Iterator, Optional

log = logging.getLogger(__name__)

__all__ = ["setup_tracing", "span", "is_enabled"]

_tracer: Any = None


def _settings():
    from control_plane.core.config import get_settings

    return get_settings()


def is_enabled() -> bool:
    return _tracer is not None


def setup_tracing(service_name: str = "bugfund", endpoint: Optional[str] = None) -> Any:
    """Initialize OTel tracing. Returns the tracer, or ``None`` if disabled."""
    global _tracer
    endpoint = endpoint or _settings().otel_endpoint
    if not endpoint:
        log.info("OTel tracing disabled (no APP_OTEL_ENDPOINT configured)")
        return None
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        log.info("OTel tracing exporting to %s", endpoint)
        return _tracer
    except Exception as exc:  # pragma: no cover - optional dependency
        log.warning("OTel tracing unavailable: %s", exc)
        return None


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Optional[Any]]:
    """Yield a span; no-op (yields ``None``) when tracing is disabled."""
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            try:
                current.set_attribute(key, value)
            except Exception:  # pragma: no cover - defensive
                pass
        yield current
