import eql

from utils import bsf2eql, eql2bsf


class EqlRuleset:
    def __init__(self, rules):
        self.rules = rules
        self.name2rule = {}
        for rule in self.rules:
            self.name2rule[rule["id"]] = rule
        self.matches = []

    def make_engine(self):
        engine = eql.PythonEngine()
        engine.add_output_hook(self)  # uses __call__ method
        for rule in self.rules:
            analytic = eql.parse_analytic({"query": rule["eql"], "metadata": rule})
            engine.add_analytic(analytic)
        return engine

    def __call__(self, result):
        rule = self.name2rule[result.analytic_id]
        for event in result.events:
            self.matches.append((eql2bsf(event), rule))

    def search(self, events, start=None, end=None):
        # create new engine to reset sequences
        engine = self.make_engine()
        for event in events:
            engine.stream_event(bsf2eql(event))
            while self.matches:
                event, rule = self.matches.pop(0)
                yield event, rule


class ElasticRuleset:
    def __init__(self, rules, event_db):
        self.rules = rules
        self.event_db = event_db
        for rule in self.rules:
            if not rule.get("sexpr"):
                rule["sexpr"] = event_db.translator.eql_to_sexpr(rule["eql"])

    def search(self, event_db, start=None, end=None):
        for rule in self.rules:
            for event in event_db.search(rule["sexpr"], start, end):
                yield event, rule
