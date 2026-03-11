import threading
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DeployJob:
    id: str
    status: str = 'pending'
    logs: List[str] = field(default_factory=list)
    result: Optional[dict] = None
    error: Optional[str] = None

    def add_log(self, message: str):
        self.logs.append(message)


_jobs: Dict[str, DeployJob] = {}
_lock = threading.Lock()


def create_job() -> DeployJob:
    job = DeployJob(id=uuid.uuid4().hex)
    with _lock:
        _jobs[job.id] = job
    return job


def get_job(job_id: str) -> Optional[DeployJob]:
    with _lock:
        return _jobs.get(job_id)
