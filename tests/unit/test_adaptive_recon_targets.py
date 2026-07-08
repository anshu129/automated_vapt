from vapt_platform.domain.enums import EventType
from vapt_platform.planning.adaptive_recon import AdaptiveReconPlanner


def test_http_service_confirmed_tolerates_numeric_base_url() -> None:
    planner = AdaptiveReconPlanner()
    payload = {"base_url": 80.0, "status_code": 200}
    items = planner.plan_from_event(EventType.HTTP_SERVICE_CONFIRMED.value, payload)
    assert items
    assert items[0].target["url"] == "80.0"
    assert items[0].target["hostname"] == "80.0"
