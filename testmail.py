import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_test_email():
    try:
        print("Creating test email...")
        
        # Email settings
        sender = "agnideesh@gmail.com"
        recipient = "agnideeshpvt@gmail.com"
        password = "skhohgqsxuykjmmy"
        smtp_server = "smtp.gmail.com"
        smtp_port = 465
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = "TEST: NIDS Email Alert System"
        
        # Email content
        body = """
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2>This is a test email from your NIDS system</h2>
            <p>If you're receiving this email, it means your email configuration is working correctly.</p>
            <p>This test was sent outside the regular alert system to verify connectivity.</p>
        </body>
        </html>
        """
        
        # Attach content
        msg.attach(MIMEText(body, 'html'))
        
        print(f"Connecting to SMTP server {smtp_server}:{smtp_port}...")
        
        # Connect using SSL
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        print("Connected to SMTP server")
        
        # Login
        print(f"Logging in as {sender}...")
        server.login(sender, password)
        print("Login successful")
        
        # Send message
        print(f"Sending test email to {recipient}...")
        server.send_message(msg)
        print("Test email sent successfully")
        
        # Quit
        server.quit()
        print("SMTP session terminated")
        
        return True
        
    except Exception as e:
        print(f"Error sending test email: {e}")
        return False

if __name__ == "__main__":
    print("Running email test script...")
    send_test_email()
    print("Test complete")