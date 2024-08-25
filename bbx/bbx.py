import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import logging
import os
from queue import Queue
import signal

import networkx as nx
import ruamel.yaml

from databases import ElasticEventDb
from detector import Detector
from investigator import Investigator
from rulesets import ElasticRuleset, EqlRuleset
from translators import Translator
from utils import abbrv, Done
from web import Web


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.DEBUG)

yaml = ruamel.yaml.YAML()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config")
    parser.add_argument("-r", "--rules-files", nargs="*")
    parser.add_argument("-a", "--activity-set-dir", default="../activity_sets/")
    parser.add_argument("-w", "--web", action="store_true")
    args = parser.parse_args()

    with open(args.config) as cfg_fp:
        cfg = yaml.load(cfg_fp)
    if not os.path.exists(args.activity_set_dir + "/history"):
        os.makedirs(args.activity_set_dir + "/history")
    logging.basicConfig(
        handlers=[
            logging.FileHandler(args.activity_set_dir + "/bbx.log"),
            logging.StreamHandler(),
        ]
    )
    rules = []
    for rules_fn in args.rules_files:
        with open(rules_fn) as rules_fp:
            rules += yaml.load(rules_fp)
    logger.debug("loaded %s rules", len(rules))
    translator = Translator(**cfg["translator"])
    event_db = ElasticEventDb(translator, **cfg["elastic"])
    first_pass = [rule for rule in rules if rule["mode"] == "first-pass"]
    second_pass = rules
    eql_ruleset = EqlRuleset(second_pass)
    es_ruleset = ElasticRuleset(first_pass, event_db)
    detector = Detector(event_db, es_ruleset)
    graph = nx.DiGraph()
    investigator = Investigator(event_db, eql_ruleset, graph)
    if args.web:
        web = Web(**cfg.get("web", {}))

    queue = Queue()
    try:
        with ThreadPoolExecutor() as executor:
            executor.submit(detection, detector, out_queue=queue, **cfg["detector"])
            executor.submit(
                investigation,
                investigator,
                in_queue=queue,
                activity_set_dir=args.activity_set_dir,
            )
            if args.web:
                executor.submit(web.run, investigator=investigator, config=cfg)
    except KeyboardInterrupt:
        signal.raise_signal(signal.SIGKILL)  # kill the process!


def detection(detector, out_queue, start=None, end=None, interval=0.0):
    logger.debug("detector starting")
    try:
        for event, alert in detector.get_alerts(start, end, interval):
            out_queue.put((event, alert))
    except Exception:
        logger.exception("An exception was raised during detection")
    out_queue.put(Done)
    logger.debug("detector completed.")


def investigation(investigator, in_queue, activity_set_dir):
    logger.debug("investigator starting")
    while True:
        try:
            item = in_queue.get()
            if item is Done:
                break
            event, alert = item
            logger.debug("investigating %s %s", abbrv(event), alert["analytic_id"])
            if event["id"] in investigator.graph.nodes:
                logger.debug("already investigated %s", abbrv(event))
                continue
            subgraph = investigator.investigate(event, alert)
            if subgraph is not None:
                activity_set = investigator.get_activity_set(event)
                logger.info(
                    "investigated %s - %s events",
                    activity_set["activity_set_id"],
                    len(subgraph.nodes),
                )
                investigator.activity_sets[
                    activity_set["activity_set_id"]
                ] = activity_set
                fn = activity_set["activity_set_id"] + ".json"
                with open(activity_set_dir + "/" + fn, "w") as fp:
                    json.dump(activity_set, fp, indent=4, sort_keys=True)
                timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M")
                fn = activity_set["activity_set_id"] + "_" + timestamp + ".json"
                with open(activity_set_dir + "/history/" + fn, "w") as fp:
                    json.dump(activity_set, fp, indent=4, sort_keys=True)
        except Exception:
            logger.exception("An exception was raised during investigation")
    logger.debug("investigator completed.")


if __name__ == "__main__":
    main()
