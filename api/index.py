from flask import Flask, send_from_directory, request, redirect, url_for, render_template

app = Flask(__name__, template_folder='../public')

@app.route('/')
def serve_html():
    return render_template('brain.html')

@app.route('/contact')
def serve_contact_page():
    return send_from_directory('../public', 'contact.html')

@app.route('/submit_contact', methods=['POST'])
def submit_contact():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']
    print(f"Name: {name}, Email: {email}, Message: {message}")
    return redirect(url_for('thank_you'))

@app.route('/thank_you')
def thank_you():
    return send_from_directory('../public', 'thank_you.html')

if __name__ == '__main__':
    app.run(debug=True)
