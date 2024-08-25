import logging

from iteration_utilities import unique_everseen
import networkx as nx
from networkx.algorithms.components import weakly_connected_components
from networkx.algorithms.components.weakly_connected import (
    # weakly_connected_components uses _plain_bsf to generate components
    _plain_bfs as node_weakly_connected_component,
)

from models import ActivitySet
from utils import abbrv, make_analytic_results, pairwise


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.DEBUG)


class EventAggregator:
    def __init__(self):
        self.flows = {}

    def aggregate(self, event):
        if event["object"] == "flow":
            flow_tup = (event["src_ip"], event["dest_port"], event["dest_ip"])
            if flow_tup in self.flows:
                self.flows[flow_tup]["count"] += 1
                return None
            else:
                event["count"] = 0
                self.flows[flow_tup] = event
        return event


class Investigator:
    def __init__(self, event_db, ruleset, graph):
        self.event_db = event_db
        self.ruleset = ruleset
        self.graph = graph
        self.start_events = {}
        self.activity_sets = {}

    def investigate(self, event, alert=None):
        subgraph = nx.DiGraph()
        subgraph.update(self.get_ancestors(event))
        subgraph.add_node(event["id"], event=event, analytic_results={})
        if alert:
            subgraph.nodes[event["id"]]["analytic_results"][alert["name"]] = alert
        self.enrich(subgraph)
        start_event = self.select_start_event(subgraph)
        if not start_event:
            logger.debug("no start event for %s", event["id"])
            return None
        logger.debug("start_event is %s", abbrv(start_event))
        self.start_events[start_event["id"]] = start_event
        subgraph.update(self.get_descendants(start_event))
        self.enrich(subgraph)
        if len(subgraph.nodes) == 1:
            logger.debug("ignoring single node graph for %s", start_event)
            return None
        self.graph.update(subgraph)
        return subgraph

    def get_ancestors(self, event):
        graph = nx.DiGraph()
        parents = list(unique_everseen(self.event_db.get_parents(event)))
        if parents:
            if len(parents) > 1:
                logger.warning(
                    f"WARNING: event {event.get('process_guid') or event.get('pid')} has multiple parents."
                )
            parent = parents[0]
            graph.update(self.get_ancestors(parent))
            graph.add_node(parent["id"], event=parent, analytic_results={})
            graph.add_edge(parent["id"], event["id"])
        return graph

    def enrich(self, graph):
        events = [node["event"] for node in graph.nodes.values() if node.get("event")]
        for event, rule in self.ruleset.search(events):
            if "attack_info" in rule:
                for analytic_result in make_analytic_results(event, rule):
                    graph.nodes[event["id"]]["analytic_results"][
                        analytic_result["analytic_result_id"]
                    ] = analytic_result
            elif "benign_info" in rule:
                graph.nodes[event["id"]]["whitelisted"] = True

    @staticmethod
    def select_start_event(graph):
        for node, next_node in pairwise(graph.nodes.values()):
            if not node.get("whitelisted") and (
                node["analytic_results"] or next_node.get("analytic_results")
            ):
                return node["event"]
        return None  # no start event

    def get_descendants(self, event, start=None, end=None):
        graph = nx.DiGraph()
        aggregator = EventAggregator()
        children = list(
            unique_everseen(
                self.event_db.get_children(event, start, end), key=lambda x: x["id"]
            )
        )  # dedup because of cg5data

        for child in children:
            child = aggregator.aggregate(child)
            if child is None:
                continue
            graph.add_node(child["id"], event=child, analytic_results={})
            graph.add_edge(event["id"], child["id"])
            # don't add descendants for children of process access, thread create, or pipe events
            if (
                not (event["object"] == "process" and event["action"] == "access")
                and not (event["object"] == "thread" and event["action"] == "create")
                and not event["object"] == "pipe"
            ):
                graph.update(self.get_descendants(child, start, end))
        return graph

    def get_activity_sets(self):
        for comp in weakly_connected_components(self.graph):
            subgraph = self.graph.subgraph(comp)
            yield ActivitySet.from_graph(subgraph)

    def get_activity_set(self, event):
        comp = node_weakly_connected_component(self.graph, event["id"])
        subgraph = self.graph.subgraph(comp)
        return ActivitySet.from_graph(subgraph)
