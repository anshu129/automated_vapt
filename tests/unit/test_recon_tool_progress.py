from vapt_platform.services import scan_jobs


def test_notify_recon_tool_event_updates_job_progress() -> None:
    job_id = "job-progress-test"
    scan_jobs._JOBS[job_id] = {
        "job_id": job_id,
        "scan_id": "abc-def-123",
        "status": "RUNNING",
        "phase": "reconnaissance",
        "progress": {},
        "created_at": "t0",
        "updated_at": "t0",
    }
    try:
        scan_jobs.notify_recon_tool_event(
            "abc-def-123",
            event="start",
            capability="DNS_RESOLUTION",
            provider="dnsx",
            target="example.com",
        )
        job = scan_jobs.get_job(job_id)
        assert job is not None
        assert job["progress"]["recon"]["current_tool"]["provider"] == "dnsx"

        scan_jobs.notify_recon_tool_event(
            "abc-def-123",
            event="done",
            capability="DNS_RESOLUTION",
            provider="dnsx",
            exit_code=0,
            duration_s=1.2,
            task_status="COMPLETED",
        )
        job = scan_jobs.get_job(job_id)
        assert job is not None
        recon = job["progress"]["recon"]
        assert "current_tool" not in recon
        assert recon["tools_completed"] == 1
        assert recon["completed_tools"][0]["exit_code"] == 0
    finally:
        scan_jobs._JOBS.pop(job_id, None)
