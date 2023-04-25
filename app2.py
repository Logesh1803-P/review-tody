import csv
# from flask import Flask, render_template, request
from flask import Flask, render_template, request, make_response
import mysql.connector
import re
import datetime;
import io

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
        
        return None

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
        
        if xss_attack_username or xss_attack_password:
            # If any kind of XSS attack is detected, block the user
            status = "Blocked"
        else:
            status = "Access granted"
        ct = datetime.datetime.now()
        Time_stamp = ct
        query = "INSERT INTO users (username, password, xss_attack_username, xss_attack_password, mac_address, status, Time_stamp ) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(query, (username, password, xss_attack_username, xss_attack_password, mac_address, status, Time_stamp))
        db.commit()
        
        if status == "Blocked":
            # Return a block message to the user
            return render_template('image.html', image_url=username, image_url2=password )
        else:
            # Return a success message to the user
            return render_template('image.html', image_url=username, image_url2=password)
    
    return render_template('index.html')

@app.route('/Attacker_list')
def Attacker_list():
    cursor.execute("SELECT * FROM users")
    data = cursor.fetchall()
    return render_template('Attacker_list.html', data=data)


# Define a route to download the table as a CSV file
@app.route('/download-csv')
def download_csv():
    # Get the data from your database
    cursor.execute("SELECT * FROM users")
    data = cursor.fetchall()
    
    # Create a CSV file in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'username', 'password', 'xss_attack_username', 'xss_attack_password', 'MAC_Address', 'status', 'Time_stamp'])
    for row in data:
        writer.writerow(row)
    
    # Return the CSV file as a response with the appropriate headers
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=users.csv'
    response.headers['Content-type'] = 'text/csv'
    return response


# Run the Flask app:
if __name__ == "__main__":
    app.run(debug=True)
