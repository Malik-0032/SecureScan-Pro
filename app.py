from flask import Flask, request, jsonify, render_template, send_file
from security_scanner import SecurityScanner  # Import your security scanner class

app = Flask(__name__, template_folder=".")

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/run_scan', methods=['POST'])
def run_scan():
    data = request.get_json()
    target_url = data.get('url')
    if not target_url:
        return jsonify({'message': 'URL is required'}), 400

    scanner = SecurityScanner(target_url)
    report = scanner.run_scan()
    return jsonify(json.loads(report))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


