import os
from flask import Flask, render_template, request, jsonify
from flask_bootstrap import Bootstrap
from tasks import check_ip_across_lists_and_policies, celery
import redis

app = Flask(__name__)
Bootstrap(app)  # <-- initialize Flask-Bootstrap

app.secret_key = 'your-secret-key'

# (optional) load Celery config into Flask config
app.config['CELERY_BROKER_URL']   = os.getenv('CELERY_BROKER_URL')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND')
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url(os.getenv('SESSION_REDIS'))
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True



@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check():
    ip = request.form.get('ip_address', '').strip()
    if not ip:
        return jsonify({'error': 'Please provide an IP address'}), 400
    # Schedule the Celery task asynchronously
    async_result = check_ip_across_lists_and_policies.apply_async((ip,), queue='default')
    # Immediately return 202 Accepted with the task ID
    return jsonify(task_id=async_result.id), 202


@app.route('/status/<task_id>', methods=['GET'])
def status(task_id):
    res = celery.AsyncResult(task_id)
    # Grab progress from .info (where update_state(meta={…}) stores it)
    percent = res.info.get('percent', 0) if isinstance(res.info, dict) else 0

    if res.state == 'PENDING':
        return jsonify({'state': res.state}), 202
    if res.state == 'PROGRESS':
        return jsonify({'state': res.state, 'percent': percent}), 202
    if res.state == 'FAILURE':
        return jsonify({'state': res.state, 'error': str(res.result)}), 500
    return jsonify({'state': res.state, 'result': res.result})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
