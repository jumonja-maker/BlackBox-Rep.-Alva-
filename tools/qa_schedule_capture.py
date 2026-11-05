"""Named, disposable Windows CI capture for decoder acceptance only.

Not a product capture policy. Fixed scheduler and CPU/file profiles use a
random owned WPR instance, including failure cleanup. The default is scheduler.
"""
from pathlib import Path
import os

from blackbox_core.windows_research import WprCapture, privilege


QA_PROFILES = {
    'schedule': ('fixtures/ThreadWaitProbe/schedule.wprp', 'BlackBoxSchedule.Verbose',
                 'OWNED_SCHEDULER_QA_MEMORY'),
    'cpu_file': ('fixtures/DecoderApps/cpu_file.wprp', 'BlackBoxCpuFile.Verbose',
                 'OWNED_CPU_FILE_QA_MEMORY'),
}


def profile_definition(profile):
    if type(profile) is not str or profile not in QA_PROFILES:
        raise ValueError('UNKNOWN_FIXED_QA_CAPTURE_PROFILE')
    return QA_PROFILES[profile]


class OwnedScheduleCapture(WprCapture):
    def __init__(self, folder, *, profile='schedule'):
        relative, entry, label = profile_definition(profile)
        if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise RuntimeError('SCHEDULER_CAPTURE_ONLY_ON_DISPOSABLE_WINDOWS_CI')
        if privilege().get('mode') != 'ADMINISTRATOR':
            raise RuntimeError('SCHEDULER_CAPTURE_REQUIRES_ADMINISTRATOR')
        super().__init__(folder)
        self.qa_profile = profile
        self.profile_entry = entry
        self.profile_label = label
        self.profile_path = Path(__file__).resolve().parent / relative
        if not self.profile_path.is_file():
            raise RuntimeError('SCHEDULER_QA_PROFILE_MISSING')

    def start(self):
        if self.active:
            raise ValueError('WPR_ALREADY_ACTIVE')
        self.active = True
        try:
            self._run(['-start', str(self.profile_path) + '!' + self.profile_entry])
        except BaseException:
            try:
                self.cancel()
            except OSError:
                pass
            raise
        return {'source': 'ETW_WPR', 'status': 'RECORDING', 'instance': self.instance,
                'profile': self.profile_label,
                'scope': 'SYSTEM_WIDE_TRACE_MAY_INCLUDE_OTHER_PROCESSES', 'lost_events': None}
