"""
Flask-based UI wrapper for the vulnerability scanner.
Run: python flask_app.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, render_template_string, request
from scanner import WebVulnScanner

app = Flask(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<title>Web Vulnerability Scanner</title>
<style>
body { font-family: Arial; margin: 30px; background: #f9f9f9; }
h2 { color: #444; }
form { margin-bottom: 20px; }
.result { background: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 0 5px #ccc; }
.vuln { color: red; }
.safe { color: green; }
</style>
</head>
<body>
<h2>🔍 Web Application Vulnerability Scanner</h2>
<form method="POST">
  <input name="url" type="text" size="50" placeholder="Enter target URL" required>
  <button type="submit">Scan</button>
</form>
{% if vulns is not none %}
<div class="result">
  <h3>Results for {{url}}</h3>
  {% if vulns %}
    <ul>
    {% for v in vulns %}
      <li class="vuln">[{{v['type']}}] {{v['url']}} — Payload: {{v['payload']}}</li>
    {% endfor %}
    </ul>
  {% else %}
    <p class="safe">✅ No vulnerabilities detected in basic scan.</p>
  {% endif %}
</div>
{% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    vulns = None
    url = None
    if request.method == "POST":
        url = request.form.get("url")
        scanner = WebVulnScanner(url)
        vulns = scanner.crawl_and_scan()
    return render_template_string(HTML_TEMPLATE, vulns=vulns, url=url)

if __name__ == "__main__":
    app.run(debug=True)
