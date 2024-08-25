import copy
from collections import defaultdict
from collections.abc import Mapping
import hashlib
import logging
import string

import eql
from elasticsearch_dsl.query import Q
from parse import parse as parse_format
import ruamel.yaml

from utils import decode_powershell, flatten


logger = logging.getLogger(__name__)

yaml = ruamel.yaml.YAML()


def immutable(self, *args, **kwargs):
    raise AttributeError(f"'{self.__class__.__name__}' object is read-only")


class frozendict(dict):
    clear = update = setdefault = pop = popitem = immutable
    __delitem__ = __setitem__ = immutable

    def __hash__(self):
        return hash(repr(self))


class frozenlist(list):
    append = clear = copy = extend = insert = pop = remove = reverse = sort = immutable
    __setitem__ = __delitem__ = __iadd__ = __imul__ = immutable

    def __hash__(self):
        return hash(repr(self))


def freeze(obj):
    if isinstance(obj, dict):
        return frozendict({k: freeze(v) for k, v in obj.items()})
    elif isinstance(obj, list):
        return frozenlist([freeze(v) for v in obj])
    return obj


class FieldFormatter(string.Formatter):
    """A custom string formatter for event/sexpr fields."""

    def get_field(self, field_name, args, kwargs):
        try:
            obj = self.get_value(field_name, args, kwargs)
            return obj, field_name
        except KeyError:
            pass
        return super().get_field(field_name, args, kwargs)

    def format_field(self, value, format_spec):
        if ":" in format_spec:
            format_spec = format_spec.split(":")[0]
        return super().format(value, format_spec)


class Translator:
    def __init__(
        self,
        mappings=None,
        escaped_fields=None,
        wildcard_suffix="",
        wildcard_suffix_fields="*",
    ):
        self.mappings = self.load_field_mappings(mappings) if mappings else []
        self.escaped_fields = escaped_fields if escaped_fields else []
        self.wildcard_suffix = wildcard_suffix
        self.wildcard_suffix_fields = wildcard_suffix_fields
        self.field_formatter = FieldFormatter()
        self.extra_types = self.load_patterns({"EXE": "[^\\\\]*$"})

    def load_patterns(self, patterns):
        extra_types = {}
        for type_name, pattern in patterns.items():
            extra_types[type_name] = lambda x: x
            extra_types[type_name].pattern = pattern
        return extra_types

    @staticmethod
    def load_field_mappings(field_mappings):
        if isinstance(field_mappings, Mapping):
            field_mappings = [field_mappings]
        elif isinstance(field_mappings, str):
            with open(field_mappings) as fp:
                field_mappings = yaml.load(fp)
        return field_mappings

    @staticmethod
    def And(queries):
        query = queries[0]
        for q in queries[1:]:
            query &= q
        return query

    @staticmethod
    def Or(queries):
        query = queries[0]
        for q in queries[1:]:
            query |= q
        return query

    def sexpr_to_elastic(self, orig_node, remap=True):
        node = orig_node
        if remap:
            node = self.remap_sexpr(orig_node)
        if isinstance(node, list):
            if node[0] == "and":
                queries = [self.sexpr_to_elastic(child) for child in node[1:]]
                return self.And(queries)
            elif node[0] == "or":
                queries = [self.sexpr_to_elastic(child) for child in node[1:]]
                return self.Or(queries)
            elif node[0] == "not":
                return ~self.sexpr_to_elastic(node[1])
            else:
                raise NotImplementedError(f"{node[0]} not implemented")
        elif isinstance(node, dict):
            field, value = tuple(node.items())[0]
            if isinstance(value, str) and field not in self.escaped_fields:
                value = value.replace("\\", "\\\\")
            if isinstance(value, str) and "*" in value:
                if isinstance(value, str) and (
                    self.wildcard_suffix_fields == "*"
                    or field in self.wildcard_suffix_fields
                ):
                    field = f"{field}{self.wildcard_suffix}"
                return Q(
                    "wildcard",
                    **{field: {"value": value.lower(), "case_insensitive": True}},
                )
            elif isinstance(value, (str, int)):
                return Q("match_phrase", **{field: value})
            else:
                raise NotImplementedError(f"{value} not implemented")
        elif node is None:
            return Q("match_none")
        else:
            raise NotImplementedError(f"{type(node)} not implemented.")

    def sexpr_to_splunk(self, orig_node, remap=True):
        node = orig_node
        if remap:
            node = self.remap_sexpr(orig_node)
        if isinstance(node, list):
            if node[0] == "and":
                queries = [self.sexpr_to_splunk(child) for child in node[1:]]
                return " ".join(queries)
            elif node[0] == "or":
                queries = [self.sexpr_to_splunk(child) for child in node[1:]]
                return "(" + " OR ".join(queries) + ")"
            elif node[0] == "not":
                return " NOT " + self.sexpr_to_splunk(node[1])
            else:
                raise NotImplementedError(f"{node[0]} not implemented")
        elif isinstance(node, dict):
            field, value = tuple(node.items())[0]
            if field not in self.escaped_fields:
                value = value.replace("\\", "\\\\")
            if isinstance(value, (str, int)):
                return f'{field}="{value}"'
            else:
                raise NotImplementedError(f"{value} not implemented")
        else:
            raise NotImplementedError(f"{type(node)} not implemented.")

    def eql_to_sexpr(self, node):
        if isinstance(node, str):
            return self.eql_to_sexpr(eql.parser.parse_query(node))
        elif isinstance(node, eql.ast.And):
            return ["and", *[self.eql_to_sexpr(term) for term in node.terms]]
        elif isinstance(node, eql.ast.Or):
            return ["or", *[self.eql_to_sexpr(term) for term in node.terms]]
        elif isinstance(node, eql.ast.PipedQuery):
            if node.pipes:
                raise NotImplementedError("pipes not implemented")
            return self.eql_to_sexpr(node.first)
        elif isinstance(node, eql.ast.EventQuery):
            query = self.eql_to_sexpr(node.query)
            if isinstance(query, list) and query[0] == "and":
                return ["and", {"object": node.event_type}, *query[1:]]
            else:
                return ["and", {"object": node.event_type}, query]
        elif isinstance(node, eql.ast.Comparison):
            field = self.eql_to_sexpr(node.left)
            value = self.eql_to_sexpr(node.right)
            if node.comparator == "==":
                return {field: value}
            elif node.comparator == "!=":
                return ["not", {field: value}]
            else:
                raise NotImplementedError(f"{node.comparator} not implemented.")
        elif isinstance(node, eql.ast.Field):
            if node.base == "subtype":
                return {"action": node.path[0]}
            return node.base
        elif isinstance(node, eql.ast.String):
            return node.value
        elif isinstance(node, eql.ast.Number):
            return node.value
        elif isinstance(node, eql.ast.FunctionCall):
            field = self.eql_to_sexpr(node.arguments[0])
            values = [self.eql_to_sexpr(value) for value in node.arguments[1:]]
            if len(values) == 1:
                return {field: values[0]}
            return ["or", *[{field: value} for value in values]]
        elif isinstance(node, eql.ast.InSet):
            field = self.eql_to_sexpr(node.expression)
            values = [self.eql_to_sexpr(value) for value in node.container]
            if len(values) == 1:
                return {field: values[0]}
            return ["or", *[{field: value} for value in values]]
        elif isinstance(node, eql.ast.Not):
            return ["not", self.eql_to_sexpr(node.term)]
        else:
            raise NotImplementedError(f"{type(node)} not implemented.")

    def remap_event(self, orig_event):
        """Remaps event fields from external format to CAR"""
        event = {}
        orig_event = flatten(orig_event)
        orig_event_items = orig_event.items()
        for field_mapping in self.mappings:
            for i, (dst, src) in enumerate(
                field_mapping.items()
            ):  # reverse src and dst
                # 1. field name mapping
                # ex: command_line: event_data.CommandLine
                # {command_line: whoami} => {event_data.CommandLine: whoami}
                if isinstance(src, str):
                    if (
                        orig_event.get(src)
                        and event.get(dst) is None
                        or event.get(dst) == "-"
                    ):
                        event[dst] = orig_event[src]
                elif isinstance(src, Mapping):
                    # 2a. field name/value mapping
                    # ex: {object: process, action: create}: {event_id: 1}
                    # {object: process}, {action: create} => {event_id: 1}
                    if any(
                        not isinstance(v, str) or "{" not in v for v in src.values()
                    ):
                        if src.items() <= orig_event_items:
                            event.update(dst)
                        elif i == 0:
                            break
                    # 2b. grok field name/value mapping
                    # ex: {exe: '{exe:EXE}'}: {event_data.Image: '*\\{exe:EXE}'}
                    # {exe: net.exe} => {event_data.Image: "*\\net.exe"}
                    else:
                        parsed_fields = {}
                        for src_fld, src_fmt in src.items():
                            src_fmt = src_fmt.replace("*", "{}")
                            try:
                                parsed_fields |= parse_format(
                                    src_fmt, orig_event[src_fld], self.extra_types
                                ).named
                            except KeyError:
                                logger.debug("No %s field in event", src_fld)
                        for dst_fld, dst_fmt in dst.items():
                            try:
                                event[dst_fld] = self.field_formatter.format(
                                    dst_fmt, **parsed_fields
                                )
                            except KeyError:
                                logger.debug("No %s field in parsed fields", dst_fld)
        if event.get("object") is None:
            ic(orig_event)
            ic(event)
        if (
            event["object"] == "process"
            and event["action"] == "create"
            and event["exe"] == "powershell.exe"
        ):
            decoded_cmds = decode_powershell(event["command_line"])
            for i, decoded_cmd in enumerate(decoded_cmds):
                event[f"decoded_command_line_{i}"] = decoded_cmd
        event["nodetype"] = "event"
        event["id"] = self.generate_event_id(event)
        event["event_id"] = event["id"]  # Rey needs this field
        event["host"] = event.get("hostname") or event.get("fqdn") or event.get("ip")
        return event

    def get_changes(self, field_mapping_item, sexpr):
        def get_sub_lists(lst, n):
            for i in range(len(lst) - n + 1):
                yield lst[i : i + n]
            for i in range(len(lst)):
                if isinstance(lst[i], list):
                    for sublist in get_sub_lists(lst[i], n):
                        yield sublist

        src, dst = field_mapping_item
        src_len = 1 if isinstance(src, str) else len(src)
        for sub_sexpr in get_sub_lists(sexpr, src_len):
            if isinstance(src, str) and src in sub_sexpr[0]:
                old = dict(sub_sexpr[0])
                new = dict({dst: v for k, v in sub_sexpr[0].items()})
                yield old, new
            elif isinstance(src, Mapping):
                is_format = any("{" in v for v in src.values())
                if not is_format and [{k: v} for k, v in src.items()] == sub_sexpr:
                    old = dict(src)
                    new = dict(dst)
                    yield old, new
                elif is_format and all(
                    src_field_name in sub_sexpr_field
                    for src_field_name, sub_sexpr_field in zip(src.keys(), sub_sexpr)
                ):
                    parsed_data = {}
                    for (
                        src_field_name,
                        src_field_value,
                    ), sub_sexpr_field in zip(src.items(), sub_sexpr):
                        parsed_data |= parse_format(
                            src_field_value, sub_sexpr_field[src_field_name]
                        ).named
                    old = dict({k: v for dct in sub_sexpr for k, v in dct.items()})
                    new = dict(
                        {
                            dst_fld_name: self.field_formatter.format(
                                dst_fld_value, **parsed_data
                            )
                            for dst_fld_name, dst_fld_value in dst.items()
                        }
                    )
                    yield old, new

    def remap_sexpr(self, sexpr):
        """Remaps sexpr fields from CAR to external format"""

        if not isinstance(sexpr, list):
            return sexpr

        all_changes = defaultdict(list)
        for mapping in self.mappings:
            mapping_items = iter(mapping.items())
            src_tgt = next(mapping_items)
            changes = list(self.get_changes(src_tgt, sexpr))
            if len(changes) == 0:
                continue  # skip the rest of this mapping
            for old, new in changes:
                if new not in all_changes[freeze(old)]:
                    all_changes[freeze(old)].append(new)
            for src_tgt in mapping_items:
                for old, new in self.get_changes(src_tgt, sexpr):
                    if new not in all_changes[freeze(old)]:
                        all_changes[freeze(old)].append(new)

        def replace_sublist(lst, sublist, replacement):
            sublist_len = len(sublist)
            main_list_len = len(lst)
            for i in range(main_list_len - sublist_len + 1):
                if lst[i : i + sublist_len] == sublist:
                    lst[i : i + sublist_len] = replacement
                    return True
            for i in range(0, len(lst)):
                if isinstance(lst[i], list):
                    if replace_sublist(lst[i], sublist, replacement):
                        return True
            return False

        new_sexpr = copy.deepcopy(sexpr)
        for old, new in all_changes.items():
            src_sexpr = [{k: v} for k, v in old.items()]
            if len(new) == 1:
                dst_sexpr = [{k: v} for k, v in new[0].items()]
            else:
                dst_sexpr = [
                    [
                        "or",
                        *[
                            dst_node
                            if len(dst_node) == 1
                            else ["and", *[{k: v} for k, v in dst_node.items()]]
                            for dst_node in new
                        ],
                    ]
                ]
            replace_sublist(new_sexpr, src_sexpr, dst_sexpr)
        return new_sexpr

    def remap_field(self, orig_field):
        for mapping in self.mappings:
            if mapping.get(orig_field):
                field = mapping.get(orig_field)
                break
        return field

    @staticmethod
    def generate_event_id(event):
        try:
            return hashlib.sha256(
                f"{event['time']}-{event['hostname']}-{event['log_name']}-{event['record_number']}".encode(
                    "utf-8"
                )
            ).hexdigest()
        except KeyError:
            logger.exception("An exception occurred during generate_event_id %s", event)
