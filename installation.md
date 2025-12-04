# Propulsion Engine Dashboard – Setup Guide
This guide explains how to install, configure, and run the Propulsion Engine Dashboard on a Raspberry Pi and connect it to the ESP32 propulsion test stand controller.

---

# 1. System Requirements

## Hardware
- Raspberry Pi 4 or Raspberry Pi 5 (recommended)
- ESP32 microcontroller connected over USB (`/dev/ttyACM0`)
- MAX6675 thermocouples, pressure sensors, ignition system, solenoid valves
- USB-C power supply for Raspberry Pi
- Local network or Wi-Fi access

## Software
- Raspberry Pi OS (64-bit recommended)
- Python 3.10+
- Git
- PostgreSQL (recommended) or SQLite
- Gunicorn (production)
- Nginx + Certbot (production with HTTPS)

---

# 2. Clone the Repository and Install Dependencies

SSH into your Raspberry Pi:

```bash
sudo apt update
sudo apt install git python3-venv python3-pip -y

git clone https://github.com/AnthonyKPhoto/Propulsion-Engine-Dashboard.git
cd Propulsion-Engine-Dashboard
Create the virtual environment:

bash
Copy code
python3 -m venv .venv
source .venv/bin/activate
Install dependencies:

bash
Copy code
pip install --upgrade pip
pip install -r requirements.txt
3. Create and Configure the .env File
Copy the example:

bash
Copy code
cp .env.example .env
nano .env
Example .env (formatted exactly like your environment file):

dotenv
Copy code
#########################################
# DATABASE CONFIGURATION
#########################################

DB_NAME=jet_dashboard
DB_USER=YOUR_DB_USERNAME
DB_PASS=YOUR_DB_PASSWORD
DB_HOST=localhost
DB_PORT=5432

# SQLAlchemy URL (for Flask)
DATABASE_URL=postgresql+psycopg://YOUR_DB_USERNAME:YOUR_DB_PASSWORD@localhost:5432/jet_dashboard
DATABASE_URL_RAW=postgresql://YOUR_DB_USERNAME:YOUR_DB_PASSWORD@localhost:5432/jet_dashboard

#########################################
# RECAPTCHA CONFIGURATION
#########################################

RECAPTCHA_PUBLIC_KEY=your_public_key
RECAPTCHA_PRIVATE_KEY=your_private_key

# Manual verification
RECAPTCHA_SITE_KEY=your_site_key
RECAPTCHA_SECRET_KEY=your_secret_key

#########################################
# FLASK SECURITY / SESSION
#########################################

SECRET_KEY=replace_with_random_string

#########################################
# SMTP CONFIGURATION
#########################################

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_email_app_password
SMTP_FROM=your_email@gmail.com
SMTP_USE_TLS=true
SMTP_FROM_ALIAS=Jet Dashboard

#########################################
# SYSTEM CONTROL
#########################################

JET_RESTART_CMD="sudo systemctl restart jet-dashboard.service"
Save and exit when done.

4. Configure PostgreSQL (If Using Postgres Recommended)
Install:

bash
Copy code
sudo apt install postgresql postgresql-contrib -y
Create DB and user:

bash
Copy code
sudo -u postgres psql
CREATE DATABASE jet_dashboard;
CREATE USER your_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE jet_dashboard TO your_user;
\q
5. Initialize the Database Models
Start Python shell:

bash
Copy code
python3
Inside Python:

python
Copy code
from app import db, create_app
app = create_app()
app.app_context().push()

db.create_all()
exit()
6. Create the First Admin User
bash
Copy code
python3
Inside Python:

python
Copy code
from app.models.user import User
from app import db, create_app
app = create_app()
app.app_context().push()

u = User(username="admin", email="admin@example.com", role="admin")
u.set_password("StrongPassword123")
db.session.add(u)
db.session.commit()
exit()
You can now log in with:

makefile
Copy code
username: admin
password: StrongPassword123
7. Run the Dashboard (Development Mode)
Activate environment:

bash
Copy code
source .venv/bin/activate
Start server:

bash
Copy code
python wsgi.py
Open in browser:

cpp
Copy code
http://<raspberry-pi-ip>:5000
8. Production Deployment (Gunicorn + Systemd)
Create service:

bash
Copy code
sudo nano /etc/systemd/system/jet-dashboard.service
Paste:

ini
Copy code
[Unit]
Description=Jet Dashboard Gunicorn Service
After=network.target

[Service]
User=pi
WorkingDirectory=/home/pi/Propulsion-Engine-Dashboard
Environment="PATH=/home/pi/Propulsion-Engine-Dashboard/.venv/bin"
ExecStart=/home/pi/Propulsion-Engine-Dashboard/.venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 wsgi:app

[Install]
WantedBy=multi-user.target
Enable and start:

bash
Copy code
sudo systemctl enable jet-dashboard
sudo systemctl start jet-dashboard
sudo systemctl status jet-dashboard
9. Nginx Reverse Proxy + HTTPS (Optional but Recommended)
Install:

bash
Copy code
sudo apt install nginx certbot python3-certbot-nginx -y
Create site:

bash
Copy code
sudo nano /etc/nginx/sites-available/jet-dashboard
Paste:

nginx
Copy code
server {
    listen 80;
    server_name dashboard.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    client_max_body_size 20m;
}
Enable:

bash
Copy code
sudo ln -s /etc/nginx/sites-available/jet-dashboard /etc/nginx/sites-enabled/
sudo systemctl restart nginx
Enable HTTPS:

bash
Copy code
sudo certbot --nginx -d dashboard.yourdomain.com
10. ESP32 Telemetry Setup
Connect ESP32 via USB.

Confirm it appears:

bash
Copy code
ls /dev/ttyACM*
Expected:

bash
Copy code
/dev/ttyACM0
Ensure .env contains:

ini
Copy code
SERIAL_DEVICE=/dev/ttyACM0
SERIAL_BAUD=115200
Telemetry will now stream into the dashboard.

11. Restart Command Permissions (Required for Admin Panel)
Give Pi user permission to restart Gunicorn:

bash
Copy code
sudo visudo
Add this line:

pgsql
Copy code
pi ALL=(ALL) NOPASSWD: /bin/systemctl restart jet-dashboard.service
Now the admin panel can reboot the service.

12. Updating the Dashboard
bash
Copy code
cd Propulsion-Engine-Dashboard
git pull
source .venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart jet-dashboard
13. Troubleshooting
Gunicorn fails to start:
bash
Copy code
sudo journalctl -u jet-dashboard -f
ESP32 not showing:
bash
Copy code
ls /dev/tty*
lsusb
Permissions error:
bash
Copy code
sudo usermod -a -G dialout pi
sudo reboot
Dashboard Successfully Installed!
