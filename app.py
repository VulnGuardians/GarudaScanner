from flask import Flask, render_template, url_for, request, flash
import subprocess
import sqlite3

app = Flask(__name__)
app.secret_key = "V1hwT1EySXhiRmhVYmtwaFYwVnJPUT09"

### Database Setup ###

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/scans')
def scans():
    return render_template('services.html')

@app.route('/base')
def base():
    return render_template('base.html')

@app.route('/contact')
def contact():
    return render_template('contact_us.html')

@app.route('/about')
def about():
    return render_template('about_us.html')

@app.route('/reach_us', methods=['POST'])
def reach_us():
    connection = sqlite3.connect('garuda.db')
    cursor = connection.cursor()
    data = [
        (request.form['name']),
        (request.form['email']),
        (request.form['message'])
    ]

    cursor.execute("insert into contact_us753(name, email, message) values(?, ?, ?)", data)
    connection.commit()
    connection.close()
    return render_template('contact_us.html')

### Scanners Here ###

@app.route('/network_scanner')
def network_scanner():
    return render_template('network_scanning.html')

@app.route('/burst_scanner')
def burst_scanner():
    return render_template('burst_scan.html')

@app.route('/deep_server_scanner')
def deep_server_scanner():
    return render_template('deep_server_scan.html')

@app.route('/directory_scanner')
def directory_scanner():
    return render_template('directory_scanner.html')

@app.route('/exploit_finder')
def exploit_finder():
    flash('Login successful!', 'success')
    return render_template('exploit_finder.html')

@app.route('/owasp_zap')
def owasp_zap():
    return render_template('owasp_zap.html')

@app.route('/sql_injection')
def sql_injection():
    return render_template('sql_injection.html')

@app.route('/sub_domain_finder')
def sub_domain_finder():
    return render_template('sub_domain_finder.html')

@app.route('/wordpress_scanner')
def wordpress_scanner():
    return render_template('wordpress_scan.html')

### Get Command from Database ###
def get_cmd(scan):
    connection = sqlite3.connect("garuda.db")
    cursor = connection.cursor()
    cursor.execute("SELECT cmd FROM commands where id=?", (scan,))
    result = cursor.fetchone()

    if result:
        return result[0]
    else:
        return None

@app.route('/anonymous', methods=['POST'])
def kevin():
    target = request.form['domain']
    scanner = request.form['scanner']

    ### Network Scanner ###
    if scanner == 'network_scanner':
        scan = 101
        cmd = get_cmd(scan)
        out = "Network Scanner"
        run_command(cmd, target)
        return render_template('output.html', out=out)

    ### Burst Scanner ###
    elif scanner == 'burst_scanner':
        scan = 102
        cmd = get_cmd(scan)
        out = "Burst Scanner"
        run_command(cmd, target)
        return render_template('output.html', out=out)

    ### Wordpress Scanner ###
    elif scanner == 'wordpress_scanner':
        scan = 103
        cmd = get_cmd(scan)
        out = "Wordpress Scanner"
        run_command(cmd, target)
        return render_template('output.html', out=out)

    ### Sub-Domain Finder ###
    elif scanner == 'subdomain_finder':
        scan = 104
        cmd = get_cmd(scan)
        out = "Sub Domain Finder"
        target = "FUZZ."+target
        run_command(cmd, target)
        return render_template('output.html', out=out)

    ### SQL Injection ###
    elif scanner == 'sql_injection':
        scan = 105
        cmd = get_cmd(scan)
        out = "SQL Injection"
        run_command(cmd, target)
        return render_template('output.html', out=out)

    ### Owasp Zap ###
    elif scanner == 'owasp_zap':
        scan = 106
        cmd = get_cmd(scan)
        out = "Owasp Zaproxy"
        run_command(cmd, target)
        return render_template('output.html', out=out)

    ### Exploit Finder ###
    elif scanner == 'exploit_finder':
        scan = 107
        cmd = get_cmd(scan)
        out = "Exploit Finder"
        run_command(cmd, target)
        return render_template('output.html', out=out)

    ### Directory Scanner ###
    elif scanner == 'directory_scanner':
        scan = 108
        cmd = get_cmd(scan)
        out = "Directory Scanenr"
        if not "http" in target:
            target = "https://"+ target
        run_command(cmd, target)
        return render_template('output.html', out=out)

    ### Deep Server Scanner ###
    elif scanner == 'deep_server_scanner':
        scan = 109
        cmd = get_cmd(scan)
        run_command(cmd, target)
        out = "Deep Server Scanner"
        return render_template('output.html', out=out)

    ### Else Part ###
    else:
        result = "Something wents wrong! Please try again."
    return render_template('output.html',out = result)

### Terminal Window ###
def run_command(cmd, target):
    cmd = cmd + " " + target
    try:
        # Open a new xterm window and run the command
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f"{cmd}; exec bash"])
    except Exception as e:
        print(f"Error Occurred: {e}")

if __name__ == "__main__":
    app.run(debug=True)