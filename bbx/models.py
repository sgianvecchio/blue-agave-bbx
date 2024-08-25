

from collections import Counter
import hashlib
import logging


logger = logging.getLogger(__name__)


def generate_edge_id(src_event_id, dest_event_id):
    return hashlib.sha256(f"{src_event_id}-{dest_event_id}".encode("utf-8")).hexdigest()


class Event(dict):
    pass


class ActivitySet(dict):
    @classmethod
    def from_graph(cls, graph):
        # sort nodes since components algorithm reorders them
        nodes = sorted(graph.nodes.values(), key=lambda x: x["event"]["time"])
        roots = [node for node in nodes if graph.in_degree(node["event"]["id"]) == 0]
        if len(roots) > 0:
            logger.info(
                "activity set %s has %s roots", roots[0]["event"]["id"], len(roots)
            )
        return cls(
            # id is the earliest event
            activity_set_id=roots[0]["event"]["id"],
            analytic_results=[
                alert for node in nodes for alert in node["analytic_results"].values()
            ],
            events=[node["event"] for node in nodes],
            edges=[
                {
                    "src_event": edge[0],
                    "dest_event": edge[1],
                    "edge_id": generate_edge_id(edge[0], edge[1]),
                }
                for edge in graph.edges
            ],
        )

    def meta(self):
        return {
            "activity_set_id": self["activity_set_id"],
            "context": {
                "analytic_result_count": len(self["analytic_results"]),
                "event_count": len(self["events"]),
                "hosts": list({event["host"] for event in self["events"]}),
                "min_time": min(event["time"] for event in self["events"]),
                "max_time": max(event["time"] for event in self["events"]),
                "tactics": dict(
                    Counter(
                        alert["attack_tactic"] for alert in self["analytic_results"]
                    )
                ),
                "techniques": dict(
                    Counter(
                        alert["attack_technique_id"]
                        for alert in self["analytic_results"]
                    )
                ),
                "users": list({event.get("user") for event in self["events"]}),
            },
        }

    def abbrv(self):
        return {
            "activity_set_id": self["activity_set_id"],
            "alert_count": len(self["analytic_results"]),
            "event_count": len(self["events"]),
            "hosts": list({event["host"] for event in self["events"]}),
            "users": " ".join(
                list({event["user"] for event in self["events"] if event.get("user")})
            ),
            "start": min(
                analytic_result["time"] for analytic_result in self["analytic_results"]
            ),
            "end": max(event["time"] for event in self["events"]),
            "tactics": " ".join(
                list(
                    {
                        alert["attack_tactic"]
                        for alert in self["analytic_results"]
                        if alert["attack_tactic"]
                    }
                )
            ),
            "techniques": " ".join(
                list(
                    {
                        alert["attack_technique_id"]
                        for alert in self["analytic_results"]
                        if alert["attack_technique_id"]
                    }
                )
            ),
        }
