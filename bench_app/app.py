import urllib.parse
from flask import Flask, request, jsonify, redirect, abort, render_template_string
from markupsafe import Markup

from bench_app.config import ALLOWED_HOSTS
from bench_app.database.connection import init_db
from bench_app.utils import file_handler, validators
from bench_app.database import queries
from bench_app.services import network_service, auth_service

app = Flask(__name__)


@app.before_request
def setup():
    init_db()


@app.route("/")
def index():
    return jsonify({"status": "running", "service": "BenchApp"})


# --- VULN-015: Server-Side Template Injection / XSS ---
@app.route("/render/preview", methods=["GET"])
def preview_template():
    """
    VULN-015: Untrusted user input rendered directly in render_template_string (SSTI / XSS).
    """
    custom_template = request.args.get("template", "Hello {{ name }}")
    name = request.args.get("name", "Guest")
    # // CASE: VULN-015
    rendered = render_template_string(custom_template, name=name)
    return rendered


# --- SAFE-013: Open Redirect False Positive bait ---
@app.route("/redirect/external", methods=["GET"])
def safe_redirect():
    """
    SAFE-013: Open redirect bait. Netloc is validated against trusted internal ALLOWED_HOSTS.
    """
    target_url = request.args.get("next", "/")
    parsed = urllib.parse.urlparse(target_url)
    # Validate destination host
    # If host is empty, it's a relative URL within same origin
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        return abort(400, "Untrusted redirect target")

    # // CASE: SAFE-013
    return redirect(target_url)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

