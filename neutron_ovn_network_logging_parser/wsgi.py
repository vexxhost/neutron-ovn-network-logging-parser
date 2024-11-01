# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import sys

import requests
from cachetools import LRUCache, cached
from flask import Flask, Response, g, request
from keystoneauth1 import loading as ks_loading
from neutron.common import config
from neutron.objects.logapi import logging_resource as log_object
from neutron_lib import context
from openstack import connection
from oslo_config import cfg

config.register_common_config_options()
config.init(sys.argv[1:])
config.setup_logging()

app = Flask(__name__)

VECTOR_HTTP_ENDPOINT = os.getenv("VECTOR_HTTP_ENDPOINT", "http://localhost:5001")
UNWANTED_LOG_FIELDS = ["host", "file", "source_type"]
NOVA_CONNECTION = None


@app.route("/logs", methods=["POST"])
def receive_logs():
    if not request.is_json:
        app.logger.error("Request must be JSON.")
        return Response(
            json.dumps(
                {
                    "status": "error",
                    "message": "Request must be JSON.",
                }
            ),
            status=400,
            mimetype="application/json",
        )

    logs = request.get_json()
    enriched_logs = parse_and_enrich_logs(logs)
    if not enriched_logs:
        app.logger.info(
            f"Ignored {len(logs)} logs not releated to neutron logging resource."
        )
        return Response(
            json.dumps(
                {
                    "status": "success",
                    "message": "Logs ignored",
                }
            ),
            status=200,
            mimetype="application/json",
        )

    if send_logs_to_vector(enriched_logs):
        app.logger.info(f"Enriched and forwared {len(enriched_logs)} logs.")
        return Response(
            json.dumps(
                {
                    "status": "success",
                    "message": "Logs received and forwarded",
                    "data": enriched_logs,
                }
            ),
            status=200,
            mimetype="application/json",
        )
    return Response(
        json.dumps(
            {
                "status": "error",
                "message": "Failed to forward logs to vector.",
                "data": enriched_logs,
            }
        ),
        status=400,
        mimetype="application/json",
    )


def parse_log_message_field(message):
    res = {}
    kv_pairs = message.split(",")
    kv_pairs.pop(0) if len(kv_pairs) > 0 else None

    for pair in kv_pairs:
        if "=" in pair:
            key, value = pair.split("=", 1)
            res[key.strip()] = value.strip()
    return res


def remove_unwanted_fields(log):
    log.pop("message", None)
    for field in UNWANTED_LOG_FIELDS:
        log.pop(field, None)
    return log


def parse_and_enrich_logs(logs):
    app.logger.debug(f"Received raw logs: {logs}")
    pattern = re.compile(r"neutron-([a-f0-9-]+)")
    enriched_logs = []
    for log in logs:
        message = log.get("message", "")
        match = pattern.search(message)
        if not match:
            continue
        network_log_id = match.group(1)
        log["network_log_id"] = network_log_id
        app.logger.debug(f"Matched network log resource id: {network_log_id}")
        project_id = get_project_id_from_network_object(network_log_id)
        app.logger.debug(f"Matched log project_id: {project_id}")
        if project_id:
            log["project_id"] = project_id
        domain_id = get_project_domain_id(project_id)
        if domain_id:
            log["domain_id"] = domain_id
        log = {
            **log,
            **parse_log_message_field(message),
        }
        log = remove_unwanted_fields(log)
        enriched_logs.append(log)
    app.logger.debug(f"Enriched logs, {enriched_logs}")
    return enriched_logs


@cached(cache=LRUCache(maxsize=128))
def get_project_id_from_network_object(network_log_id):
    try:
        ctx = context.get_admin_context()
        logs = log_object.Log.get_objects(ctx, id=network_log_id)
        if len(logs) == 0:
            app.logger.error(f"No match neutron log object found. id: {network_log_id}")
            return None
        return logs[0].project_id
    except Exception as e:
        app.logger.error(
            f"Error retrieving project id from network log object {network_log_id}: {e}"
        )
    return None


@cached(cache=LRUCache(maxsize=128))
def get_project_domain_id(project_id):
    try:
        # NOTE(okozachenko1203): this method uses Nova Keystone user to retrieve the
        # project because (1) it is allowed to retrieve the projects and (2)
        # Neutron avoids adding another user section in the configuration
        # (Nova user will be always used).
        global NOVA_CONNECTION
        if not NOVA_CONNECTION:
            auth = ks_loading.load_auth_from_conf_options(cfg.CONF, "nova")
            keystone_session = ks_loading.load_session_from_conf_options(
                cfg.CONF, "nova", auth=auth
            )
            NOVA_CONNECTION = connection.Connection(
                session=keystone_session,
                oslo_conf=cfg.CONF,
                connect_retries=cfg.CONF.http_retries,
            )
        project_obj = NOVA_CONNECTION.get_project(project_id)
        if not project_obj:
            app.logger.error(f"Project {project_id} does not exist")
        return project_obj.domain_id

    except Exception as e:
        app.logger.error(
            f"Error retrieving domain id from project id {project_id}: {e}"
        )

    return None


def send_logs_to_vector(logs):
    try:
        response = requests.post(VECTOR_HTTP_ENDPOINT, json=logs)
        if response.status_code != 200:
            app.logger.error(f"Failed to send logs to Vector: {response.text}")
            return False
        return True
    except Exception as e:
        app.logger.error(f"Error sending logs to Vector: {e}")
        return False


app.route("/health", methods=["GET"])


def health_check():
    return Response(status=200)


def create_app():
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=9697)
