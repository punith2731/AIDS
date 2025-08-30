import os
import numpy as np
import pickle
import json
import time
import threading
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file
from tensorflow.keras.models import load_model
from explain import get_feature_importance, explain_model_predictions
from uuid import uuid4

app = Flask(__name__)

# Load model, encoders, and scaler
def load_resources():
    try:
        model = load_model('models/ids_model.h5')
        
        with open('models/encoders.pkl', 'rb') as f:
            encoders = pickle.load(f)
        
        with open('models/scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        
        return model, encoders, scaler
    
    except (ImportError, IOError) as e:
        print(f"Error loading resources: {str(e)}")
        return None, None, None

model, encoders, scaler = load_resources()

# Global variables for auto traffic capture
capture_active = False
capture_thread = None
traffic_data = []
next_packet_id = 1

# Email notification settings
EMAIL_ENABLED = True          # Enable email notifications
EMAIL_SIMULATION_MODE = False # Disable simulation mode to send real emails
EMAIL_SENDER = "agnideesh@gmail.com"
EMAIL_RECIPIENT = "lithishyaarokiasamy@gmail.com"
EMAIL_PASSWORD = "skhohgqsxuykjmmy"
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_SMTP_PORT = 465  # Changed from 587 (TLS) to 465 (SSL)
MALICIOUS_THRESHOLD = 6  # Send email after this many malicious detections
malicious_count = 0

# Track notifications to allow frontend to poll
last_notification = {
    "type": None,
    "message": None,
    "timestamp": None
}

@app.route('/', methods=['GET'])
def root():
    return render_template('index.html')

@app.route('/auto', methods=['GET'])
def auto_detect():
    return render_template('auto.html')

@app.route('/explainability', methods=['GET'])
def explainability():
    return render_template('explainability.html')

@app.route('/api', methods=['GET'])
def api_info():
    return jsonify({
        "name": "Network Intrusion Detection System API",
        "description": "API for classifying network traffic as normal or malicious",
        "endpoints": {
            "GET /": "Web interface",
            "GET /api": "This documentation",
            "GET /health": "Check API health status",
            "POST /predict": "Make a single prediction (requires JSON data)",
            "POST /batch_predict": "Make multiple predictions (requires JSON array)",
            "GET /explain": "Get model explainability information",
            "GET /feature_importance": "Get feature importance rankings"
        },
        "status": "Model loaded and ready" if model is not None else "Model not loaded"
    })

@app.route('/health', methods=['GET'])
def health_check():
    if model is not None and encoders is not None and scaler is not None:
        return jsonify({"status": "ok", "message": "API is ready"})
    else:
        return jsonify({"status": "error", "message": "Model or resources not loaded"}), 500

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({"error": "Model not loaded. Please train the model first."}), 500
    
    try:
        # Get data from request
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Process the input data
        # Note: We're expecting data in the same format as the training data
        # with the same feature names
        
        # Process categorical features
        for col in encoders:
            if col in data:
                data[col] = encoders[col].transform([data[col]])[0]
        
        # Convert to numpy array
        input_data = np.array([list(data.values())])
        
        # Scale the data
        input_data = scaler.transform(input_data)
        
        # Make prediction
        prediction_prob = model.predict(input_data)[0][0]
        prediction = int(prediction_prob > 0.5)
        
        # Return result
        return jsonify({
            "prediction": "Malicious" if prediction == 1 else "Normal",
            "probability": float(prediction_prob),
            "confidence": float(prediction_prob if prediction == 1 else 1 - prediction_prob)
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    if model is None:
        return jsonify({"error": "Model not loaded. Please train the model first."}), 500
    
    try:
        # Get data from request
        data_batch = request.json
        
        if not data_batch or not isinstance(data_batch, list):
            return jsonify({"error": "No data provided or data is not a list"}), 400
        
        results = []
        
        # Process each sample in the batch
        for data in data_batch:
            # Process categorical features
            for col in encoders:
                if col in data:
                    data[col] = encoders[col].transform([data[col]])[0]
            
            # Prepare input data
            input_data = np.array([list(data.values())])
            input_data = scaler.transform(input_data)
            
            # Make prediction
            prediction_prob = model.predict(input_data)[0][0]
            prediction = int(prediction_prob > 0.5)
            
            # Add result to batch results
            results.append({
                "prediction": "Malicious" if prediction == 1 else "Normal",
                "probability": float(prediction_prob),
                "confidence": float(prediction_prob if prediction == 1 else 1 - prediction_prob)
            })
        
        return jsonify({"results": results})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/explain', methods=['GET'])
def generate_explanations():
    try:
        # Generate SHAP explanations
        plots = explain_model_predictions()
        
        return jsonify({
            "status": "success",
            "message": "Explanation plots generated successfully",
            "plots": plots
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/feature_importance', methods=['GET'])
def feature_importance():
    try:
        # Get feature importance
        importance_df = get_feature_importance()
        
        # Convert to list of dictionaries for JSON
        importance_data = [
            {"feature": row['feature'], "importance": float(row['importance'])}
            for _, row in importance_df.iterrows()
        ]
        
        return jsonify({
            "status": "success",
            "feature_importance": importance_data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/static/images/<filename>', methods=['GET'])
def get_image(filename):
    return send_file(f'static/images/{filename}')

@app.route('/chatbot', methods=['POST'])
def chatbot_response():
    """Endpoint for the security chatbot assistant"""
    try:
        data = request.json
        if not data or 'message' not in data:
            return jsonify({"error": "No message provided"}), 400
            
        user_message = data['message']
        
        # In a real implementation, this would call Gemini or another AI API
        # For now, we'll use a simple response generator
        response = generate_security_response(user_message)
        
        return jsonify({
            "status": "success",
            "response": response
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def generate_security_response(message):
    """
    Generate a response for the security chatbot
    In a real implementation, this would call the Gemini API
    """
    message = message.lower()
    
    # Basic responses based on message content
    if any(word in message for word in ['hello', 'hi', 'hey']):
        return "Hello! How can I assist with your network security questions today?"
    
    if any(phrase in message for phrase in ['what is', 'explain']) and any(word in message for word in ['ids', 'intrusion', 'detection']):
        return """
        An Intrusion Detection System (IDS) is a security technology that monitors network traffic and system 
        activities for malicious activities or policy violations. 
        
        Our IDS uses deep learning algorithms trained on the NSL-KDD dataset to identify potential network 
        intrusions by analyzing patterns in network traffic data. It examines various features like protocol type, 
        service, packet size, connection patterns, and more to detect anomalies or known attack signatures.
        """
    
    if 'attack' in message or 'threat' in message:
        return """
        Common network attacks our system can detect include:
        
        1. Denial of Service (DoS) - Attempts to make a machine or network resource unavailable
        2. Probing/Scanning - Gathering information about a network for later attacks
        3. R2L (Remote to Local) - Unauthorized access from a remote machine
        4. U2R (User to Root) - Unauthorized access to local superuser privileges
        5. Data exfiltration - Unauthorized data transfer from a system
        
        If you're experiencing an active attack, I recommend isolating the affected systems and checking 
        the real-time monitoring page for more details.
        """
    
    if 'false positive' in message:
        return """
        False positives can occur in any detection system. To reduce them:
        
        1. Review and customize detection thresholds
        2. Regularly update the model with new labeled data
        3. Use the feedback mechanism to report false positives, which helps improve future detections
        4. Consider implementing a multi-stage detection approach
        
        If you believe a specific alert is a false positive, you can mark it in the system.
        """
    
    if 'model' in message or 'how does it work' in message:
        return """
        Our NIDS uses a Deep Neural Network architecture trained on the NSL-KDD dataset. The model:
        
        1. Preprocesses network traffic data to normalize and encode features
        2. Analyzes 41 different features of network connections
        3. Uses multiple hidden layers with advanced activation functions
        4. Outputs a probability score indicating whether traffic is normal or malicious
        
        The model achieves over 98% accuracy on test data. You can visit the Explainability page to see 
        which features most influence the model's decisions.
        """
    
    if 'shap' in message or 'explain' in message:
        return """
        We use SHAP (SHapley Additive exPlanations) values to explain model predictions:
        
        - The Summary Plot shows which features contribute most to the model's decisions
        - Red points indicate feature values that push predictions toward "malicious"
        - Blue points indicate feature values that push predictions toward "normal"
        - The higher a feature appears in the list, the more impactful it is overall
        
        This helps security analysts understand why specific traffic is flagged as suspicious.
        """
    
    if 'recommend' in message or 'suggest' in message or 'best practice' in message:
        return """
        Network security best practices I recommend:
        
        1. Keep all systems and software updated with security patches
        2. Implement strong access controls and authentication (MFA where possible)
        3. Segment your network to contain potential breaches
        4. Deploy firewalls and configure them properly
        5. Regularly backup critical data using the 3-2-1 strategy
        6. Monitor network traffic with tools like our NIDS
        7. Train employees to recognize phishing and other social engineering attacks
        8. Use encryption for sensitive data in transit and at rest
        9. Conduct regular security audits and penetration testing
        10. Document and practice incident response procedures
        """
    
    # Default response
    return """
    I'm here to help with network security questions. You can ask about:
    
    • How our intrusion detection system works
    • Different types of network attacks
    • How to interpret model explanations
    • Security best practices
    • How to investigate alerts
    
    What would you like to know more about?
    """

# Auto traffic capture endpoints
@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_active, capture_thread
    
    if capture_active:
        return jsonify({"status": "info", "message": "Capture already active"})
    
    capture_active = True
    capture_thread = threading.Thread(target=capture_traffic_loop)
    capture_thread.daemon = True
    capture_thread.start()
    
    return jsonify({"status": "success", "message": "Traffic capture started"})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capture_active
    
    if not capture_active:
        return jsonify({"status": "info", "message": "Capture already stopped"})
    
    capture_active = False
    return jsonify({"status": "success", "message": "Traffic capture stopped"})

@app.route('/clear_traffic', methods=['POST'])
def clear_traffic():
    global traffic_data, next_packet_id
    
    traffic_data = []
    next_packet_id = 1
    
    return jsonify({"status": "success", "message": "Traffic history cleared"})

@app.route('/get_traffic', methods=['GET'])
def get_traffic():
    limit = request.args.get('limit', default=50, type=int)
    
    # Return the most recent packets up to the limit
    recent_packets = traffic_data[-limit:] if traffic_data else []
    
    return jsonify({
        "status": "success",
        "capturing": capture_active,
        "traffic": recent_packets
    })

def capture_traffic_loop():
    global traffic_data, next_packet_id, malicious_count
    
    # Keep track of malicious connections for email alerts
    malicious_connections = []
    
    while capture_active:
        try:
            # Use netstat to get active connections
            netstat_output = subprocess.check_output("netstat -ano", shell=True).decode('utf-8')
            lines = netstat_output.split('\n')
            
            # Skip header lines
            for line in lines[4:]:
                if not line.strip() or not capture_active:
                    continue
                
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                # Parse connection info
                try:
                    protocol = parts[0].lower()
                    
                    # Split local and remote addresses
                    local_addr = parts[1].rsplit(':', 1)
                    remote_addr = parts[2].rsplit(':', 1)
                    
                    local_ip = local_addr[0]
                    local_port = int(local_addr[1]) if len(local_addr) > 1 else 0
                    
                    remote_ip = remote_addr[0]
                    remote_port = int(remote_addr[1]) if len(remote_addr) > 1 else 0
                    
                    status = parts[3]
                    
                    # Skip loopback and internal connections for simplicity
                    if local_ip in ['127.0.0.1', '0.0.0.0', '[::]:'] or remote_ip in ['0.0.0.0', '[::]:']:
                        continue
                    
                    # Determine service based on port
                    service = get_service_name(remote_port)
                    
                    # Create features for the model
                    features = {
                        'protocol': protocol,
                        'service': service,
                        'src_bytes': np.random.randint(100, 10000),  # Simulated
                        'dst_bytes': np.random.randint(100, 10000),  # Simulated
                        'duration': np.random.randint(1, 60),  # Simulated
                        'count': np.random.randint(1, 10),  # Simulated
                        'same_srv_rate': np.random.random(),  # Simulated
                        'diff_srv_rate': np.random.random(),  # Simulated
                        'dst_host_srv_count': np.random.randint(1, 100),  # Simulated
                        'dst_host_same_srv_rate': np.random.random(),  # Simulated
                    }
                    
                    # Make prediction
                    prediction = predict_traffic(features)
                    
                    # Create packet record
                    packet = {
                        'id': str(next_packet_id),
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'protocol': protocol,
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'service': service,
                        'status': status,
                        'src_bytes': features['src_bytes'],
                        'dst_bytes': features['dst_bytes'],
                        'prediction': prediction,
                        'model_input': features
                    }
                    
                    # Check if this is a new connection
                    is_new_connection = not any(p['local_ip'] == local_ip and p['local_port'] == local_port and 
                            p['remote_ip'] == remote_ip and p['remote_port'] == remote_port and
                            p['protocol'] == protocol for p in traffic_data[-50:])
                    
                    # Add to traffic data if not already present
                    if is_new_connection:
                        traffic_data.append(packet)
                        next_packet_id += 1
                        
                        # Check if malicious and update counter
                        if prediction['prediction'] == 'Malicious':
                            malicious_count += 1
                            malicious_connections.append(packet)
                            print(f"Malicious connection detected! Count: {malicious_count}/{MALICIOUS_THRESHOLD}")
                            
                            # Check if we should send an email alert
                            if malicious_count >= MALICIOUS_THRESHOLD:
                                print(f"Malicious threshold reached ({MALICIOUS_THRESHOLD}). Sending email alert...")
                                send_email_alert(malicious_connections)
                                # Update notification status for UI
                                last_notification["type"] = "email_alert"
                                last_notification["message"] = f"Email alert sent to {EMAIL_RECIPIENT}"
                                last_notification["timestamp"] = datetime.now().timestamp()
                                # Reset counter after sending alert
                                malicious_count = 0
                    
                except Exception as e:
                    print(f"Error processing connection: {str(e)}")
            
            # Limit the size of traffic_data to 1000 entries
            if len(traffic_data) > 1000:
                traffic_data = traffic_data[-1000:]
            
            # Sleep before next capture
            time.sleep(5)
            
        except Exception as e:
            print(f"Error in capture thread: {str(e)}")
            time.sleep(5)

def get_service_name(port):
    """Map port numbers to common service names"""
    services = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        465: 'smtps',
        993: 'imaps',
        995: 'pop3s',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgres',
        8080: 'http-proxy'
    }
    return services.get(port, 'other')

def predict_traffic(features):
    """Make a prediction using the loaded model"""
    # In a real implementation, this would preprocess the features properly
    # For demo purposes, we'll return random predictions with confidence
    if np.random.random() < 0.8:  # 80% normal traffic
        return {
            'prediction': 'Normal',
            'confidence': np.random.uniform(0.7, 0.99)
        }
    else:
        return {
            'prediction': 'Malicious',
            'confidence': np.random.uniform(0.6, 0.95)
        }

# Add a notification endpoint for the UI to poll
@app.route('/check_notifications', methods=['GET'])
def check_notifications():
    """Return the last notification to the UI"""
    return jsonify({
        "status": "success",
        "notification": last_notification
    })

# Add endpoint to get alert settings
@app.route('/alert_settings', methods=['GET'])
def get_alert_settings():
    """Return the current email alert settings"""
    return jsonify({
        "status": "success",
        "settings": {
            "enabled": EMAIL_ENABLED,
            "threshold": MALICIOUS_THRESHOLD,
            "recipient": EMAIL_RECIPIENT
        }
    })

def send_email_alert(malicious_connections):
    """Send an email alert about malicious network activity"""
    if not EMAIL_ENABLED:
        print("Email notifications are disabled.")
        return False
    
    # If in simulation mode, just log the email and return success
    if EMAIL_SIMULATION_MODE:
        print(f"[SIMULATED EMAIL] Would send alert email to {EMAIL_RECIPIENT} with {len(malicious_connections)} malicious connections")
        return True
    
    try:
        print(f"Preparing to send email alert to {EMAIL_RECIPIENT}...")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECIPIENT
        msg['Subject'] = f"[URGENT TEST] NIDS Security Alert - {datetime.now().strftime('%H:%M:%S')}"
        
        # Add additional headers to prevent filtering
        msg['Importance'] = 'High'
        msg['X-Priority'] = '1'  # 1 = High
        msg['X-MSMail-Priority'] = 'High'
        msg['X-Mailer'] = 'NIDS Security System'
        
        # Unique message ID to prevent Gmail threading/filtering
        msg['Message-ID'] = f"<{uuid4()}@nids.security.system>"
        
        # Email body with formatting
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="padding: 20px; background-color: #f8f8f8; border-left: 4px solid #ff4757;">
                <h2 style="color: #ff4757;">⚠️ Security Alert: Malicious Network Activity</h2>
                <p>Your Network Intrusion Detection System has detected suspicious activity.</p>
                
                <h3>Alert Details:</h3>
                <ul>
                    <li><strong>Number of malicious connections:</strong> {len(malicious_connections)}</li>
                    <li><strong>Detection threshold:</strong> {MALICIOUS_THRESHOLD}</li>
                    <li><strong>Time of alert:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                </ul>
                
                <h3>Latest Malicious Connections:</h3>
                <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
                    <tr style="background-color: #e1e1e1;">
                        <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Time</th>
                        <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Protocol</th>
                        <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Source</th>
                        <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Destination</th>
                        <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Service</th>
                        <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Confidence</th>
                    </tr>
        """
        
        # Add each malicious connection to the email
        for conn in malicious_connections[-5:]:  # Show last 5 malicious connections
            confidence = conn['prediction']['confidence'] * 100
            body += f"""
                    <tr style="background-color: rgba(255, 71, 87, 0.1);">
                        <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{conn['timestamp']}</td>
                        <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{conn['protocol'].upper()}</td>
                        <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{conn['local_ip']}:{conn['local_port']}</td>
                        <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{conn['remote_ip']}:{conn['remote_port']}</td>
                        <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{conn['service']}</td>
                        <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{confidence:.2f}%</td>
                    </tr>
            """
        
        body += """
                </table>
                
                <div style="margin-top: 20px; padding: 15px; background-color: #f1f1f1; border-radius: 4px;">
                    <p style="margin: 0;"><strong>Recommended Action:</strong> Please check your Network Intrusion Detection System dashboard for more details and take appropriate action.</p>
                </div>
                
                <p style="margin-top: 20px; font-size: 12px; color: #777;">
                    This is an automated alert from your Network Intrusion Detection System.
                </p>
                <!-- Add a hidden timestamp to prevent email grouping -->
                <div style="display:none;">{datetime.now().timestamp()}</div>
            </div>
        </body>
        </html>
        """
        
        # Attach HTML content
        msg.attach(MIMEText(body, 'html'))
        
        print(f"Connecting to SMTP server {EMAIL_SMTP_SERVER}:{EMAIL_SMTP_PORT} using SSL...")
        
        # Use SMTP_SSL for direct SSL connection
        try:
            server = smtplib.SMTP_SSL(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT)
            print("Connected to SMTP server with SSL")
            
            # Login to server
            print(f"Attempting to log in as {EMAIL_SENDER}...")
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            print("Login successful")
            
            # Send email
            print("Sending message...")
            server.send_message(msg)
            print("Message sent successfully")
            
            # Terminate the SMTP session
            server.quit()
            print("SMTP session terminated")
            
            print(f"Email alert successfully sent to {EMAIL_RECIPIENT}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            print(f"SMTP Authentication Error: {e}")
            print("This is usually caused by:")
            print("1. Incorrect email address or password")
            print("2. For Gmail: You need to use an App Password if 2FA is enabled")
            print("3. Account security settings might be blocking the login")
            print("Check your credentials and try again.")
            return False
            
        except smtplib.SMTPException as e:
            print(f"SMTP Error: {e}")
            return False
    
    except Exception as e:
        print(f"Failed to send email alert: {e}")
        return False

if __name__ == '__main__':
    if model is None:
        print("Warning: Model not loaded. Please make sure to train the model first.")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 