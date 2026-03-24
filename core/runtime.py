import threading
import uuid
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DeployJob:
    id: str
    status: str = 'pending'
    logs: List[str] = field(default_factory=list)
    result: Optional[dict] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def add_log(self, message: str):
        self.logs.append(message)


_jobs: Dict[str, DeployJob] = {}
_lock = threading.Lock()


def create_job() -> DeployJob:
    job = DeployJob(id=uuid.uuid4().hex)
    with _lock:
        _jobs[job.id] = job
        if len(_jobs) > 100:
            oldest_key = list(_jobs.keys())[0]
            del _jobs[oldest_key]
    return job


def get_job(job_id: str) -> Optional[DeployJob]:
    with _lock:
        return _jobs.get(job_id)
