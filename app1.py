from flask import Flask, render_template, request
import mysql.connector
import re

# Create a Flask app and define the database connection:

app = Flask(__name__)

db = mysql.connector.connect(
     host="localhost",
     user="root",
     password="1803",
     database="xss_attacks"
)
cursor = db.cursor()

# Reflected XSS detection pattern
reflected_xss_pattern = re.compile(r'<script>|<\/script>|<img|<svg|alert\(|confirm\(|prompt\(|javascript:', re.IGNORECASE)

# DOM-based XSS detection pattern
dom_xss_pattern = re.compile(r'document\.|window\.|eval\(|\$\(|\$\$|\$\$\$|\(\)\.innerHTML|location\.href', re.IGNORECASE)

def detect_xss(payload):
    
    if dom_xss_pattern.search(payload):
        
        return "DOM-based XSS attack detected!"
    elif reflected_xss_pattern.search(payload):
       
        return "Reflected XSS attack detected!"
    else:
        
        return "No XSS attack detected."

# Create a route to handle the form submission:
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mac_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        # Check for XSS attacks
        xss_attack_username = detect_xss(username)
        xss_attack_password = detect_xss(password)
        
        query = "INSERT INTO users (username, password, xss_attack_username, xss_attack_password, mac_address) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (username, password, xss_attack_username, xss_attack_password, mac_address))
        db.commit()
        
        # return 'Submitted successfully!'
        return render_template('image.html', image_url=username)
    
    return render_template('index.html')

@app.route('/Attacker_list')
def v_timestamp():
    cursor.execute("SELECT * FROM users")
    data = cursor.fetchall()
    return render_template('Attacker_list.html', data=data)

# Run the Flask app:
if __name__ == "__main__":
    app.run(debug=True)
