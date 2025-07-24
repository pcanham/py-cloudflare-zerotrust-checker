import os
from flask import Flask, render_template, request, jsonify
from flask_bootstrap import Bootstrap
from tasks import check_ip_across_zero_trust_and_policies, celery

app = Flask(__name__)
Bootstrap(app)  # <-- initialize Flask-Bootstrap

# (optional) load Celery config into Flask config
app.config['CELERY_BROKER_URL']   = os.getenv('CELERY_BROKER_URL')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND')


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check():
    ip = request.form.get('ip_address', '').strip()
    if not ip:
        return jsonify({'error': 'Please provide an IP address'}), 400

    task = check_ip_across_zero_trust_and_policies.delay(ip)
    return jsonify({'task_id': task.id}), 202


@app.route('/status/<task_id>', methods=['GET'])
def status(task_id):
    res = celery.AsyncResult(task_id)
    if res.state == 'PENDING':
        return jsonify({'state': res.state}), 202
    if res.state == 'FAILURE':
        return jsonify({'state': res.state, 'error': str(res.result)}), 500
    return jsonify({'state': res.state, 'result': res.result})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
