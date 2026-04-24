import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_bootstrap import Bootstrap
from tasks import check_ip_across_lists_and_policies, celery
from features_config import FEATURE_FLAGS


app = Flask(__name__)
Bootstrap(app)

app.config['FEATURE_FLAGS'] = FEATURE_FLAGS

# Secret key for session signing
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Celery configuration
app.config["CELERY_BROKER_URL"] = os.getenv("CELERY_BROKER_URL")
app.config["CELERY_RESULT_BACKEND"] = os.getenv("CELERY_RESULT_BACKEND")


def is_feature_enabled(feature_name):
    return app.config['FEATURE_FLAGS'].get(feature_name, False)


@app.route("/", methods=["GET"])
def index():
    task_id = session.get("task_id")
    if task_id == "None":
        task_id = None
    last_checked_ip = session.get("last_checked_ip")
    if last_checked_ip == "None":
        last_checked_ip = None
    if is_feature_enabled("port"):
        last_checked_port = session.get("last_checked_port")
        if last_checked_port == "None":
            last_checked_port = None
        return render_template(
            "index_ports.html", task_id=task_id, last_checked_ip=last_checked_ip, last_checked_port=last_checked_port, features=app.config['FEATURE_FLAGS'])
    else:
        return render_template(
            "index.html", task_id=task_id, last_checked_ip=last_checked_ip, features=app.config['FEATURE_FLAGS'])


@app.route("/check", methods=["POST"])
def check():
    port = request.form.get("port", "").strip()
    ip = request.form.get("ip_address", "").strip()
    if not ip:
        return jsonify({"error": "Please provide an IP address"}), 400
    # Schedule the Celery task asynchronously
    async_result = check_ip_across_lists_and_policies.apply_async(
        (ip, port), queue="default"
    )
    # Store task_id and IP in session
    session["task_id"] = async_result.id
    session["last_checked_ip"] = ip
    if is_feature_enabled("port"):
        session["last_checked_port"] = port
    return jsonify(task_id=async_result.id), 202


@app.route("/status/<task_id>", methods=["GET"])
def status(task_id):
    res = celery.AsyncResult(task_id)
    info = res.info if isinstance(res.info, dict) else {}
    percent = info.get("percent", 0)
    step = info.get("step", "")

    if res.state == "PENDING":
        return jsonify({"state": res.state}), 202
    if res.state == "PROGRESS":
        return jsonify({"state": res.state, "percent": percent, "step": step}), 202
    if res.state == "FAILURE":
        return jsonify({"state": res.state, "error": str(res.result)}), 500
    if res.state == "SUCCESS":
        session.pop("task_id", None)
        return jsonify({"state": res.state, "result": res.result})
    return jsonify({"state": res.state}), 202


@app.route("/reset-session", methods=["GET"])
def reset_session():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
