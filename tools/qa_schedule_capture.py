"""Named, disposable Windows CI capture for decoder acceptance only.

Not a product capture policy. The explicit repo profile guarantees scheduler
events; a random owned WPR instance is always used, including failure cleanup.
"""
from pathlib import Path
import os

from blackbox_core.windows_research import WprCapture, privilege


class OwnedScheduleCapture(WprCapture):
    def __init__(self, folder):
        if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise RuntimeError('SCHEDULER_CAPTURE_ONLY_ON_DISPOSABLE_WINDOWS_CI')
        if privilege().get('mode') != 'ADMINISTRATOR':
            raise RuntimeError('SCHEDULER_CAPTURE_REQUIRES_ADMINISTRATOR')
        super().__init__(folder)
        self.profile_path = Path(__file__).resolve().parent/'fixtures/ThreadWaitProbe/schedule.wprp'
        if not self.profile_path.is_file():
            raise RuntimeError('SCHEDULER_QA_PROFILE_MISSING')

    def start(self):
        if self.active:
            raise ValueError('WPR_ALREADY_ACTIVE')
        self.active = True
        try:
            self._run(['-start', str(self.profile_path)+'!BlackBoxSchedule.Verbose'])
        except BaseException:
            try:
                self.cancel()
            except OSError:
                pass
            raise
        return {'source': 'ETW_WPR', 'status': 'RECORDING', 'instance': self.instance,
                'profile': 'OWNED_SCHEDULER_QA_MEMORY',
                'scope': 'SYSTEM_WIDE_TRACE_MAY_INCLUDE_OTHER_PROCESSES', 'lost_events': None}
