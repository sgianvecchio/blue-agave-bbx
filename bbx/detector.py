from datetime import timedelta
import logging
import time

from utils import make_analytic_results


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.DEBUG)


class Detector:
    def __init__(self, event_db, ruleset):
        self.event_db = event_db
        self.ruleset = ruleset

    def get_alerts(self, start=None, end=None, interval=0.0):
        cur = self.event_db.get_time()
        while start and cur < start:
            logger.debug("sleeping until %s", start)
            time.sleep((start - cur).total_seconds())
            cur = self.event_db.get_time()
        while end and cur < end:
            logger.debug("searching %s %s", start, cur)
            for event, rule in self.ruleset.search(self.event_db, start, cur):
                for alert in make_analytic_results(event, rule):
                    yield event, alert
            time.sleep(interval)
            start = cur + timedelta(microseconds=1)
            cur = self.event_db.get_time()
        logger.debug("searching %s %s", start, end)
        for event, rule in self.ruleset.search(self.event_db, start, end):
            for alert in make_analytic_results(event, rule):
                yield event, alert
