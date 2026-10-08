from sentinelscan.models import PortResult, PortState


def test_port_result_to_dict() -> None:
    result = PortResult(port=80, state=PortState.OPEN, latency_ms=1.5)
    assert result.to_dict() == {
        "port": 80,
        "state": "open",
        "latency_ms": 1.5,
        "error": None,
    }


def test_port_result_is_frozen() -> None:
    result = PortResult(port=80, state=PortState.CLOSED)
    try:
        result.port = 81
    except AttributeError:
        return
    raise AssertionError("PortResult should be immutable")