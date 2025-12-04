# Propulsion Engine Dashboard – Installation Guide
This guide explains how to install, configure, and run the Propulsion Engine Dashboard on a Raspberry Pi using an ESP32 for telemetry and control.

---

## 1. Requirements

### Hardware
- Raspberry Pi 4 or Raspberry Pi 5  
- ESP32 (USB connection via `/dev/ttyACM0`)  
- MAX6675 thermocouples, pressure sensors  
- Solenoid valves / ignition hardware  
- Stable 5V USB-C power supply  
- Local network access  

### Software
- Raspberry Pi OS (64-bit)  
- Python 3.10+  
- Git  
- PostgreSQL or SQLite  
- Gunicorn + Nginx (optional production)

---

## 2. Clone the Repository

```bash
sudo apt update
sudo apt install git python3-venv python3-pip -y

git clone https://github.com/AnthonyKPhoto/Propulsion-Engine-Dashboard.git
cd Propulsion-Engine-Dashboard
3. Create the Virtual Environment
bash
Copy code
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
4. Configure Environment Variables
bash
Copy code
cp .env.example .env
nano .env
Example .env:

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

DATABASE_URL=postgresql+psycopg://YOUR_DB_USERNAME:YOUR_DB_PASSWORD@localhost:5432/jet_dashboard
DATABASE_URL_RAW=postgresql://YOUR_DB_USERNAME:YOUR_DB_PASSWORD@localhost:5432/jet_dashboard

#########################################
# RECAPTCHA (Optional)
#########################################

RECAPTCHA_PUBLIC_KEY=
RECAPTCHA_PRIVATE_KEY=
RECAPTCHA_SITE_KEY=
RECAPTCHA_SECRET_KEY=

#########################################
# FLASK SECURITY
#########################################

SECRET_KEY=replace_with_random_string

#########################################
# SMTP (Email)
#########################################

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_USE_TLS=true
SMTP_FROM_ALIAS=Jet Dashboard

#########################################
# SYSTEM CONTROL
#########################################

JET_RESTART_CMD="sudo systemctl restart jet-dashboard.service"
5. Initialize the Database
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
6. Create an Admin User
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

admin = User(
    username="admin",
    email="admin@example.com",
    role="admin",
    is_approved=True
)
admin.set_password("StrongPassword123")

db.session.add(admin)
db.session.commit()
exit()
7. Run the Dashboard (Development Mode)
bash
Copy code
source .venv/bin/activate
python wsgi.py
Dashboard URL:

cpp
Copy code
http://<raspberry-pi-ip>:5000
8. Production Deployment (Gunicorn + Systemd)
Create the service:

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
Enable + start:

bash
Copy code
sudo systemctl enable jet-dashboard
sudo systemctl start jet-dashboard
9. ESP32 Telemetry Setup
Check for device:

bash
Copy code
ls /dev/ttyACM*
Set in .env:

ini
Copy code
SERIAL_DEVICE=/dev/ttyACM0
SERIAL_BAUD=115200
10. Enable Restart Permission for Admin Panel
bash
Copy code
sudo visudo
Add:

pgsql
Copy code
pi ALL=(ALL) NOPASSWD: /bin/systemctl restart jet-dashboard.service
11. Update the Dashboard
bash
Copy code
git pull
source .venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart jet-dashboard
12. Troubleshooting
View Gunicorn logs
bash
Copy code
sudo journalctl -u jet-dashboard -f
Check ESP32 connection
bash
Copy code
lsusb
ls /dev/tty*
Fix permissions
bash
Copy code
sudo usermod -a -G dialout pi
sudo reboot
Installation Complete
