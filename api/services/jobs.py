from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
from threading import BoundedSemaphore, Lock
from uuid import uuid4

from api.security.policy import ServiceError

log = logging.getLogger("aegis.jobs")


class JobManager:
    """One heavy operation, one waiting slot, bounded retained results."""
    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="aegis-scan")
        self.slots = BoundedSemaphore(2)
        self.lock = Lock()
        self.jobs = {}

    def submit(self, case_id, operation):
        if not self.slots.acquire(blocking=False):
            raise ServiceError("The scan worker is busy. Wait for a running job to finish.", 429)
        job_id = str(uuid4())
        with self.lock:
            for key in list(self.jobs):
                if len(self.jobs) < 30:
                    break
                if self.jobs[key]["status"] in {"completed", "failed", "cancelled"}:
                    del self.jobs[key]
            self.jobs[job_id] = dict(id=job_id, case_id=case_id, status="queued", phase="Waiting for worker",
                progress=None, result=None, error=None, cancellable=True,
                created_at_utc=datetime.now(timezone.utc).isoformat())

        def run():
            with self.lock:
                self.jobs[job_id].update(status="running", phase="Analyzing verified evidence", cancellable=False)
            try:
                def progress(checked, total, _path):
                    with self.lock:
                        self.jobs[job_id]["progress"] = dict(checked=checked, total=total)
                result = operation(progress)
                with self.lock:
                    self.jobs[job_id].update(status="completed", phase="Complete", result=result)
            except Exception as exc:
                log.warning("job_failed id=%s type=%s", job_id, type(exc).__name__)
                message = str(exc) if isinstance(exc, ServiceError) else "Analysis could not complete. Check evidence schema, integrity and selected capability."
                with self.lock:
                    self.jobs[job_id].update(status="failed", phase="Failed", error=message)
            finally:
                self.slots.release()
        future = self.pool.submit(run)
        with self.lock:
            self.jobs[job_id]["future"] = future
        return self.get(case_id, job_id)

    def get(self, case_id, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None or job['case_id'] != case_id:
                raise ServiceError("Job not found in this case.", 404)
            return {k: v for k, v in job.items() if k != "future"}

    def cancel(self, case_id, job_id):
        self.get(case_id, job_id)
        with self.lock:
            job = self.jobs[job_id]
            if job['status'] != 'queued' or not job['future'].cancel():
                raise ServiceError("This engine cannot cancel a running operation; queued jobs can be cancelled.", 409)
            job.update(status="cancelled", phase="Cancelled", cancellable=False)
            self.slots.release()
        return self.get(case_id, job_id)

    def close(self):
        self.pool.shutdown(wait=True, cancel_futures=True)
