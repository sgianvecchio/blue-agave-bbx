from datetime import datetime, timezone
import logging

import elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Q
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.DEBUG)


class EventDb:
    @staticmethod
    def get_time():
        return datetime.now(timezone.utc)

    def get_process(self, process_guid):
        query = [
            "and",
            {"object": "process"},
            {"action": "create"},
            {"process_guid": process_guid},
        ]
        return next(self.search(query))

    def get_children(self, event, start=None, end=None):
        if event["object"] == "process" and event["action"] == "create":
            query = [
                "and",
                [
                    "or",
                    # non-process-create/non-process-access children
                    [
                        "and",
                        [
                            "not",
                            [
                                "or",
                                ["and", {"object": "process"}, {"action": "create"}],
                                ["and", {"object": "process"}, {"action": "access"}],
                            ],
                        ],
                        {"process_guid": event["process_guid"]},
                    ],
                    # process-create children
                    [
                        "and",
                        {"parent_process_guid": event["process_guid"]},
                        {"parent_exe": event["exe"]},
                    ],
                    # process-access children
                    [
                        "and",
                        {"object": "process"},
                        {"action": "access"},
                        {"src_process_guid": event["process_guid"]},
                    ],
                    # thread-create children
                    [
                        "and",
                        {"object": "thread"},
                        {"action": "create"},
                        {"src_process_guid": event["process_guid"]},
                    ],
                    # scriptblock-execute children
                    [
                        "and",
                        {"object": "script_block"},
                        {"action": "execution"},
                        {"pid": event["pid"]},
                    ],
                ],
                {"hostname": event["host"]},
            ]
        elif event["object"] == "process" and event["action"] == "access":
            query = [
                "and",
                {"object": "process"},
                {"action": "create"},
                {"process_guid": event["process_guid"]},
                {"hostname": event["host"]},
            ]
        elif event["object"] == "thread" and event["action"] == "create":
            query = [
                "and",
                {"object": "process"},
                {"action": "create"},
                {"process_guid": event["tgt_process_guid"]},
                {"hostname": event["host"]},
            ]
        elif (
            event["object"] == "pipe"
            and event["action"] == "create"
            and event["pipe_name"] != "&lt;Anonymous Pipe&gt;"
        ):
            query = [
                "and",
                {"object": "pipe"},
                {"action": "connect"},
                {"pipe_name": event["pipe_name"]},
                {"hostname": event["host"]},
            ]
        else:
            query = None
        return self.search(query, start, end) if query else []

    def get_parents(self, event):
        if event["object"] == "process" and event["action"] == "create":
            query = [
                "and",
                {"object": "process"},
                {"action": "create"},
                {"process_guid": event["parent_process_guid"]},
                {"hostname": event["host"]},
            ]
        elif event["object"] == "script_block" and event["action"] == "execute":
            query = [
                "and",
                {"object": "process"},
                {"action": "create"},
                {"pid": event["pid"]},
                {"exe": "powershell.exe"},
                {"hostname": event["host"]},
            ]
        elif event["object"] == "process" and event["action"] == "access":
            query = [
                "and",
                {"object": "process"},
                {"action": "create"},
                {"process_guid": event["src_process_guid"]},
                {"hostname": event["host"]},
            ]
        else:
            query = [
                "and",
                {"object": "process"},
                {"action": "create"},
                {"process_guid": event["process_guid"]},
                {"hostname": event["host"]},
            ]
        return self.search(query)


class ElasticEventDb(EventDb):
    def __init__(self, translator, index, **kwargs):
        self.translator = translator
        self.index = index
        self.es = elasticsearch.Elasticsearch(**kwargs)

    def search(self, query, start=None, end=None, sort=False, size=None):
        es_query = self.translator.sexpr_to_elastic(query)
        time_field = self.translator.remap_field("time")
        es_query &= Q("range", **{time_field: {"gte": start, "lte": end}})
        search = Search(using=self.es, index=self.index).filter(es_query)
        if sort:
            search = search.sort(f"-{time_field}")
        if size:
            search = search.extra(size=size)
            results = search.execute()
        else:
            results = search.scan()
        results = list(results)  # delete
        for hit in results:
            yield self.translator.remap_event(hit.to_dict())
