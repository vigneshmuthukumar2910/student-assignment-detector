from flask import Flask, render_template, request, redirect, url_for, session, flash
import pandas as pd
from transformers import pipeline
import torch
import os
from werkzeug.utils import secure_filename

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Initialize AI Detector
device = "cuda" if torch.cuda.is_available() else "cpu"
ai_detector = pipeline("text-classification", 
                      model="roberta-base-openai-detector", 
                      device=device)

# Setup database files
if not os.path.exists("users.csv"):
    pd.DataFrame(columns=["username", "password", "role"]).to_csv("users.csv", index=False)
if not os.path.exists("submissions.csv"):
    pd.DataFrame(columns=["file", "content", "result", "student"]).to_csv("submissions.csv", index=False)
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Create admin account if missing
if os.path.exists("users.csv"):
    users = pd.read_csv("users.csv")
    if "admin" not in users["username"].values:
        pd.concat([users, pd.DataFrame([["admin", "admin123", "teacher"]], 
                 columns=["username", "password", "role"])]).to_csv("users.csv", index=False)
else:
    pd.DataFrame([["admin", "admin123", "teacher"]], 
                columns=["username", "password", "role"]).to_csv("users.csv", index=False)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'register' in request.form:
            return register()
        
        username = request.form['username']
        password = request.form['password']
        
        users = pd.read_csv("users.csv")
        user = users[(users["username"] == username) & (users["password"] == password)]
        
        if not user.empty:
            session['username'] = username
            session['role'] = user["role"].values[0]
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

def register():
    username = request.form['reg_username']
    password = request.form['reg_password']
    
    if len(username) < 4 or len(password) < 4:
        flash('Username and password must be at least 4 characters', 'error')
        return redirect(url_for('login'))
    
    users = pd.read_csv("users.csv")
    if username in users["username"].values:
        flash('Username already exists', 'error')
        return redirect(url_for('login'))
    
    new_user = pd.DataFrame([[username, password, "student"]], 
                          columns=["username", "password", "role"])
    users = pd.concat([users, new_user])
    users.to_csv("users.csv", index=False)
    
    flash('Student account created successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session['role'] == 'student':
        return render_template('student.html', username=session['username'])
    else:
        submissions = pd.read_csv("submissions.csv").to_dict('records')
        return render_template('teacher.html', 
                            username=session['username'],
                            submissions=submissions)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
    
    if file and file.filename.endswith('.txt'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read(5000)
            
            if len(content) < 20:
                flash('File is too short (min 20 chars)', 'error')
                return redirect(url_for('dashboard'))
                
            result = ai_detector(content[:1000])[0]
            detection = f"{result['label']} ({result['score']*100:.1f}%)"
            
            df = pd.read_csv("submissions.csv")
            new_entry = pd.DataFrame([[filename, content, detection, session['username']]], 
                                   columns=["file", "content", "result", "student"])
            df = pd.concat([df, new_entry])
            df.to_csv("submissions.csv", index=False)
            
            flash(f'File submitted! AI Detection: {detection}', 'success')
        except Exception as e:
            flash(f'Upload failed: {str(e)}', 'error')
    else:
        flash('Only .txt files are allowed', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/view/<filename>')
def view_content(filename):
    if 'username' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    df = pd.read_csv("submissions.csv")
    submission = df[df["file"] == filename].iloc[0]
    
    return render_template('view_content.html', 
                         filename=filename,
                         content=submission['content'],
                         result=submission['result'],
                         student=submission['student'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)