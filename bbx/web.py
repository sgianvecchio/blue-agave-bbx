import json
import logging
import os
import traceback

from flask import Flask, render_template
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash


auth = HTTPBasicAuth()
app = Flask(__name__)

inv = None

flaskLogger = logging.getLogger("werkzeug")
flaskLogger.setLevel(logging.ERROR)
logger = logging.getLogger(__name__)


@auth.verify_password
def verify_password(username, password):
    users = {
        "bbx": generate_password_hash(os.environ.get("BBX_WEB_PASSWORD", "")),
    }
    if username in users and check_password_hash(users.get(username), password):
        return username


@app.route("/activity_set/<event_id>")
def get_activity_set(event_id):
    data = {"activity_set": inv.get_activity_set({"id": event_id})}
    return json.dumps({"data": data}, sort_keys=True)


@app.route("/activity_set/meta")
def get_activity_set_meta():
    data = []
    for activity_set in inv.get_activity_sets():
        data.append(activity_set.meta())
    return json.dumps({"data": data})


@app.route("/abbrv_activity_sets")
def abbrv_activity_sets():
    return json.dumps(
        [activity_set.abbrv() for activity_set in inv.activity_sets.values()]
    )


@app.route("/")
@auth.login_required
def web_page():
    return render_template("index.html", bbate_host=cfg.get("bbate_host"))


class Web:
    def __init__(self, port=8080):
        self.port = port

    def run(self, investigator, config):
        try:
            global inv
            global cfg
            inv = investigator
            cfg = config
            logger.info("launching web server")
            app.run(host="0.0.0.0", port=self.port)
        except Exception:
            traceback.print_exc()
