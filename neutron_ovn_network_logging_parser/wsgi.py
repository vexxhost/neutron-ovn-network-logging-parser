# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import sys

import requests

from flask import Flask, Response, g, request
from neutron.common import config

from neutron.objects.logapi import logging_resource as log_object

config.register_common_config_options()
config.init(sys.argv[1:])
config.setup_logging()

app = Flask(__name__)

VECTOR_HTTP_ENDPOINT = os.getenv("VECTOR_HTTP_ENDPOINT", "http://localhost:5001")


@app.route('/logs', methods=['POST'])
def receive_logs():
    if not request.is_json:
        return Response(
            json.dumps({
                "status": "error",
                "message": "Request must be JSON.",
            }),
            status=400,
            mimetype='application/json'
        )

    logs = request.get_json()
    enriched_logs = parse_and_enrich_logs(logs)
    if send_logs_to_vector(enriched_logs):
        return Response(
            json.dumps({
                "status": "success",
                "message": "Logs received and forwarded",
                "data": enriched_logs,
            }),
            status=200,
            mimetype='application/json'
        )
    return Response(
        json.dumps({
            "status": "error",
            "message": "Failed to forward logs to vector.",
            "data": enriched_logs,
        }),
        status=400,
        mimetype='application/json'
    )


def parse_and_enrich_logs(logs):
    pattern = re.compile(r'neutron-([a-f0-9-]+)')
    enriched_logs = []
    for log in logs:
        message = log.get("message", "")
        match = pattern.search(message)
        if match:
            network_log_id = match.group(1)
            project_id = get_project_id_from_network_object(network_log_id)
            if project_id:
                log["project_id"] = project_id
        enriched_logs.append(log)
    return enriched_logs


def get_project_id_from_network_object(network_log_id):
    try:
        log_object.Log.get_objects(g.ctx, id=network_log_id)
        if log_object:
            return log_object.project_id
    except Exception as e:
        app.logger.error(f"Error retrieving project id from network log object {network_log_id}: {e}")
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


app.route('/health', methods=['GET'])
def health_check():
    return Response(status=200)


def create_app():
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=9697)
