import sqlite3
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify

app = Flask(__name__)

# Database setup
db_name = "argentina_corrupta.db"

def init_db():
    with sqlite3.connect(db_name) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            confirmed INTEGER DEFAULT 0
                          )''')
        conn.commit()

init_db()

# Email setup
SMTP_SERVER = "smtp.gmail.com"  # Replace with your SMTP server
SMTP_PORT = 587
EMAIL_ADDRESS = "joacodheredia@gmail.com"  # Replace with your email
EMAIL_PASSWORD = "Joaco51016314"  # Replace with your email password

def send_confirmation_email(to_email, username):
    try:
        confirmation_link = f"http://127.0.0.1:5000/confirm?email={to_email}"
        subject = "Confirma tu registro en Argentina Corrupta"
        body = f"Hola {username},\n\nGracias por registrarte en Argentina Corrupta. Por favor, confirma tu registro haciendo clic en el siguiente enlace:\n{confirmation_link}\n\nSaludos,\nEl equipo de Argentina Corrupta."

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = to_email

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        print("Correo de confirmación enviado.")
    except Exception as e:
        print(f"Error enviando correo: {e}")

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"error": "Faltan campos obligatorios."}), 400

    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, password))
            conn.commit()
        send_confirmation_email(email, username)
        return jsonify({"message": "Usuario registrado exitosamente. Verifica tu correo para confirmar."}), 201
    except sqlite3.IntegrityError as e:
        return jsonify({"error": "El usuario o correo ya está registrado."}), 400

@app.route('/confirm', methods=['GET'])
def confirm_email():
    email = request.args.get('email')

    if not email:
        return "Falta el parámetro de correo electrónico.", 400

    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET confirmed = 1 WHERE email = ?", (email,))
            if cursor.rowcount == 0:
                return "Correo no encontrado o ya confirmado.", 404
            conn.commit()
        return "Correo confirmado exitosamente. Ahora puedes iniciar sesión.", 200
    except Exception as e:
        return f"Error confirmando correo: {e}", 500

if __name__ == '__main__':
    app.run(debug=True)
