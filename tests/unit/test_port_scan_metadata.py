from vapt_platform.planning.port_scan import apply_port_scan_metadata, http_service_port


def test_apply_port_scan_metadata_merges_without_alias_mutation() -> None:
    existing = {"dns_resolved": True, "dns_status": "COMPLETE"}
    updated = apply_port_scan_metadata(
        existing,
        {
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "10.2",
            "source": "nmap",
        },
    )
    assert existing == {"dns_resolved": True, "dns_status": "COMPLETE"}
    assert updated["open_ports"] == [22]
    assert updated["services"][0]["service"] == "ssh"


def test_apply_port_scan_metadata_accumulates_ports() -> None:
    first = apply_port_scan_metadata(
        {},
        {"port": 22, "protocol": "tcp", "service": "ssh", "source": "nmap"},
    )
    second = apply_port_scan_metadata(
        first,
        {"port": 80, "protocol": "tcp", "service": "http", "source": "nmap"},
    )
    assert second["open_ports"] == [22, 80]
    assert len(second["services"]) == 2


def test_http_service_port_filters_non_web_services() -> None:
    assert http_service_port(80, "http") is True
    assert http_service_port(22, "ssh") is False
    assert http_service_port(8080, None) is True
