from flask import Flask, render_template, request, redirect, url_for
import requests
import base64
import time
import re

app = Flask(__name__)

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def get_virustotal_endpoint(endpoint_type):
    encoded_endpoints = {
        'submit': 'aHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20vYXBpL3YzL3VybHM=',
        'analysis': 'aHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20vYXBpL3YzL2FuYWx5c2VzLw=='
    }
    return base64.urlsafe_b64decode(encoded_endpoints[endpoint_type] + "==").decode()

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def submit_url(api_key, url):
    if not is_valid_url(url):
        raise ValueError("Invalid URL format. Please enter a valid URL.")
    
    endpoint = get_virustotal_endpoint('submit')
    headers = {'x-apikey': api_key, 'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'url': url}
    response = requests.post(endpoint, headers=headers, data=payload)
    if response.status_code == 200:
        return response.json().get('data', {}).get('id')
    elif response.status_code == 401:
        raise ValueError("Unauthorized request. Please check your API key.")
    else:
        raise Exception(f"Error submitting URL for scanning. Status code: {response.status_code}")

def get_analysis(api_key, analysis_id):
    endpoint = get_virustotal_endpoint('analysis') + analysis_id
    headers = {'x-apikey': api_key}
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 200:
        return response.json().get('data', {}).get('attributes', {})
    else:
        raise Exception(f"Error retrieving analysis results. Status code: {response.status_code}")

def calculate_threat_score(stats):
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    score = (malicious * 2) + suspicious
    return score

def scan_url(url, api_key):
    try:
        analysis_id = submit_url(api_key, url)
        print("URL submitted for scanning successfully. Waiting for analysis...")
        time.sleep(10)
        analysis_data = get_analysis(api_key, analysis_id)
        stats = analysis_data.get('stats', {})
        detected_threats = analysis_data.get('results', {})
        
        print("URL Reputation:", stats)
        print("Detected Threats:")
        for engine, result in detected_threats.items():
            category = result.get('category', 'unrated')
            engine_result = result.get('result', 'clean')
            print(f"- {engine}: {engine_result} ({category})")
        
        threat_score = calculate_threat_score(stats)
        print(f"Custom Threat Score: {threat_score}")
        if threat_score > 0:
            print("The URL has been flagged by several antivirus engines. Proceed with caution.")
        else:
            print("The URL seems safe to access.")
        
        return {
            "stats": stats,
            "threats": detected_threats,
            "threat_score": threat_score
        }
    except ValueError as e:
        print(e)
        return {"error": str(e)}
    except Exception as e:
        print(e)
        return {"error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    api_key = '51c90fd5d2edb90bc65a84673d61d26ae13a781377f7b2f7519b606236ddf292'  # Replace with your actual VirusTotal API key
    result = scan_url(url, api_key)
    return render_template('result.html', url=url, result=result)

if __name__ == '__main__':
    app.run(debug=True)
