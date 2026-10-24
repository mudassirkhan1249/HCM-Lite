import os, tempfile, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient

tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False); tmp.close()
os.environ['DATABASE_URL'] = 'sqlite:///' + tmp.name
os.environ['SEED_DEMO_DATA'] = 'false'
os.environ['ADMIN_EMAIL'] = 'company.admin@example.test'
os.environ['ADMIN_PASSWORD'] = 'TestAdminPass!234'
os.environ['SECRET_KEY'] = 'test-secret-key-for-tests-only'
from app.main import app, init_db
init_db()
client = TestClient(app)

def login(email, password, role):
    r=client.post('/api/auth/login',json={'email':email,'password':password,'role':role})
    assert r.status_code==200, r.text
    return {'Authorization':'Bearer '+r.json()['access_token']}

def test_health():
    r=client.get('/api/health'); assert r.status_code==200 and r.json()['status']=='ok'

def test_only_company_admin_is_bootstrapped():
    a=login('company.admin@example.test','TestAdminPass!234','admin')
    assert client.get('/api/dashboard',headers=a).status_code==200
    with __import__('sqlite3').connect(tmp.name) as c:
        assert c.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 1
        assert c.execute('SELECT COUNT(*) FROM employees').fetchone()[0] == 0
        assert c.execute('SELECT COUNT(*) FROM departments').fetchone()[0] == 0

def test_wrong_role_rejected():
    r=client.post('/api/auth/login',json={'email':'company.admin@example.test','password':'TestAdminPass!234','role':'employee'})
    assert r.status_code==401

def test_employee_cannot_view_audit():
    assert client.get('/api/audit').status_code==401
