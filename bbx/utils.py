import base64
import datetime
import gzip
import hashlib
import json
import re

import eql


class DoneType(object):
    pass


Done = DoneType()


def abbrv(event):
    return (
        f"{event['object']} {event['action']} {event.get('exe') or ''} "
        + f"{event.get('command_line') or ''} "
        + f"{event.get('process_guid') or event.get('pid')} {event['id']}"
    )


def decode_powershell(cmd):
    prog = re.compile(
        r"[^A-Za-z0-9+/]((?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})+)(?:[^A-Za-z0-9+/]|$)"
    )
    encoded_cmds = prog.findall(cmd)
    decoded_cmds = []
    while encoded_cmds:
        decoded_cmd = ""
        for encoded_cmd in encoded_cmds:
            try:
                decoded_cmd_bytes = base64.b64decode(encoded_cmd)
                try:
                    decoded_cmd_bytes = gzip.decompress(decoded_cmd_bytes)
                except gzip.BadGzipFile:
                    pass
                decoded_cmd = decoded_cmd_bytes.decode(
                    json.detect_encoding(decoded_cmd_bytes)
                )
                decoded_cmds.append(decoded_cmd)
                break
            except UnicodeDecodeError:
                continue
        encoded_cmds = prog.findall(decoded_cmd)
    return decoded_cmds


def flatten(event):
    new_event = {}

    def recurse(subdict, partial_key):
        for k, v in subdict.items():
            new_key = k if partial_key is None else f"{partial_key}.{k}"
            if isinstance(v, dict):
                recurse(v, new_key)
            else:
                new_event[new_key] = v

    recurse(event, partial_key=None)
    return new_event


def generate_analytic_result_id(event_id, rule_id, technique_id, tactic):
    return hashlib.sha256(
        f"{event_id}-{rule_id}-{technique_id}-{tactic}".encode("utf-8")
    ).hexdigest()


def make_analytic_results(event, rule):
    for technique in rule.get("attack_info", []):
        analytic_result = {
            "analytic_id": rule["id"],
            "analytic_name": rule["name"],
            "name": rule["name"],
            "analytic_result_id": generate_analytic_result_id(
                event["id"], rule["id"], technique["technique_id"], technique["tactics"]
            ),
            "attack_tactic": technique["tactics"][0],
            "attack_technique_id": technique["technique_id"],
            "key_event": event["id"],
            "time": event["time"],
        }
        if rule["mode"] == "first-pass":
            analytic_result["alert_id"] = analytic_result["analytic_result_id"]
        yield analytic_result


def pairwise(it):
    lst = list(it)
    return zip(lst, lst[1:] + [{}])


def bsf2eql(event):
    event["event_type"] = event["object"]
    event["subtype"] = event["action"]
    # https://ehmatthes.com/blog/faster_than_strptime/
    event["timestamp"] = (
        datetime.datetime.fromisoformat(
            event["time"].replace("Z", "+00:00")
        ).timestamp()
        * 1000
    )
    return eql.Event.from_data(event)


def eql2bsf(event):
    event = event.copy().data
    del event["event_type"]
    del event["subtype"]
    del event["timestamp"]
    return event