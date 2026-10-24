from __future__ import annotations
import os, json, base64, hashlib, hmac, secrets, sqlite3, math, calendar, io
from datetime import datetime, date, timedelta, timezone
from pathlib import Path
from typing import Optional
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / '.env')
DATA = ROOT / 'data'; DATA.mkdir(exist_ok=True)
DB_PATH = os.getenv('DATABASE_URL','sqlite:///./data/hcm_lite.db').replace('sqlite:///','')
if not os.path.isabs(DB_PATH): DB_PATH = str((ROOT / DB_PATH).resolve())
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
SECRET = os.getenv('SECRET_KEY','dev-only-change-me')
TOKEN_MIN = int(os.getenv('ACCESS_TOKEN_MINUTES','480'))

app = FastAPI(title='HCM Lite Pro', version='2.0.0', description='Role-scoped HR, attendance, leave, payroll and face recognition prototype')
app.mount('/static', StaticFiles(directory=str(ROOT/'frontend')), name='static')

@contextmanager
def db():
    conn=sqlite3.connect(DB_PATH, timeout=15); conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    try: yield conn; conn.commit()
    finally: conn.close()

def now_iso(): return datetime.now().astimezone().isoformat(timespec='seconds')
def today(): return date.today().isoformat()
def hash_password(pw: str, salt: Optional[str]=None):
    salt=salt or secrets.token_hex(16); digest=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt.encode(),210000).hex(); return f'{salt}${digest}'
def verify_password(pw, stored):
    try:
        salt,digest=stored.split('$',1); return hmac.compare_digest(hash_password(pw,salt).split('$',1)[1],digest)
    except Exception: return False
def token_for(user):
    payload={'sub':user['id'],'role':user['role'],'exp':int(datetime.now(timezone.utc).timestamp())+TOKEN_MIN*60}
    raw=base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).decode().rstrip('=')
    sig=hmac.new(SECRET.encode(),raw.encode(),hashlib.sha256).hexdigest()
    return raw+'.'+sig
def decode_token(token):
    try:
        raw,sig=token.rsplit('.',1); expected=hmac.new(SECRET.encode(),raw.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,expected): return None
        payload=json.loads(base64.urlsafe_b64decode(raw+'='*((4-len(raw)%4)%4)))
        if payload['exp'] < int(datetime.now(timezone.utc).timestamp()): return None
        return payload
    except Exception: return None

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','hr','employee')), employee_id INTEGER, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS departments(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, manager_id INTEGER, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS employees(id INTEGER PRIMARY KEY, employee_code TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, department_id INTEGER, designation TEXT, hire_date TEXT, salary REAL DEFAULT 0, status TEXT DEFAULT 'active', manager_id INTEGER, face_embedding TEXT, created_at TEXT NOT NULL, FOREIGN KEY(department_id) REFERENCES departments(id));
        CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL, work_date TEXT NOT NULL, check_in TEXT, check_out TEXT, status TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'web', note TEXT, UNIQUE(employee_id,work_date), FOREIGN KEY(employee_id) REFERENCES employees(id));
        CREATE TABLE IF NOT EXISTS leave_types(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, annual_quota REAL NOT NULL DEFAULT 12, paid INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS leave_requests(id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL, leave_type_id INTEGER NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL, days REAL NOT NULL, reason TEXT, status TEXT NOT NULL DEFAULT 'pending', reviewer_id INTEGER, review_note TEXT, created_at TEXT NOT NULL, FOREIGN KEY(employee_id) REFERENCES employees(id), FOREIGN KEY(leave_type_id) REFERENCES leave_types(id));
        CREATE TABLE IF NOT EXISTS payroll(id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL, month TEXT NOT NULL, gross REAL NOT NULL, tax REAL NOT NULL, deductions REAL NOT NULL, net REAL NOT NULL, finalized INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, UNIQUE(employee_id,month), FOREIGN KEY(employee_id) REFERENCES employees(id));
        CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, author_id INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, actor_id INTEGER, action TEXT NOT NULL, entity TEXT NOT NULL, entity_id TEXT, details TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, message TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS holidays(id INTEGER PRIMARY KEY, holiday_date TEXT UNIQUE NOT NULL, name TEXT NOT NULL);
        ''')
        # Fresh company setup: create ONLY the configured company admin. No demo users,
        # employees, departments, attendance, leave types, or announcements are seeded.
        if c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']==0:
            admin_email = os.getenv('ADMIN_EMAIL', '').strip()
            admin_password = os.getenv('ADMIN_PASSWORD', '')
            if not admin_email or not admin_password or admin_password == 'CHANGE_ME_TO_A_LONG_UNIQUE_PASSWORD':
                raise RuntimeError('Fresh database setup requires ADMIN_EMAIL and ADMIN_PASSWORD in .env. Set a strong unique ADMIN_PASSWORD before starting.')
            c.execute('INSERT INTO users(email,password_hash,role,created_at) VALUES (?,?,?,?)', (admin_email, hash_password(admin_password), 'admin', now_iso()))

def audit(c, actor, action, entity, entity_id=None, details=None):
    c.execute('INSERT INTO audit_log(actor_id,action,entity,entity_id,details,created_at) VALUES (?,?,?,?,?,?)',(actor,action,entity,str(entity_id) if entity_id is not None else None,json.dumps(details or {}),now_iso()))

def current_user(authorization: Optional[str]=Header(default=None)):
    if not authorization or not authorization.lower().startswith('bearer '): raise HTTPException(401,'Login required')
    payload=decode_token(authorization.split(' ',1)[1]);
    if not payload: raise HTTPException(401,'Session expired or invalid')
    with db() as c: user=c.execute('SELECT * FROM users WHERE id=? AND active=1',(payload['sub'],)).fetchone()
    if not user: raise HTTPException(401,'Account disabled')
    return dict(user)
def require(*roles):
    def dep(u=Depends(current_user)):
        if u['role'] not in roles: raise HTTPException(403,'Your role does not have permission for this action')
        return u
    return dep

def visible_employee_ids(c,u):
    if u['role']=='admin': return [r['id'] for r in c.execute('SELECT id FROM employees')]
    if u['role']=='hr': return [r['id'] for r in c.execute("SELECT id FROM employees WHERE department_id=(SELECT department_id FROM employees WHERE id=?)",(u['employee_id'],))]
    return [u['employee_id']] if u['employee_id'] else []

def public_user(u):
    return {'id':u['id'],'email':u['email'],'role':u['role'],'employee_id':u['employee_id']}

class LoginIn(BaseModel): email: str; password: str; role: str
class EmployeeIn(BaseModel):
    full_name: str = Field(min_length=2,max_length=120); email: str; department_id: int; designation: str='Employee'; hire_date: str=Field(default_factory=today); salary: float=Field(default=0,ge=0); password: str=Field(default='ChangeMe@123',min_length=8)
class LeaveIn(BaseModel): leave_type_id: int; start_date: str; end_date: str; reason: str=''
class ReviewIn(BaseModel): status: str; review_note: str=''
class DepartmentIn(BaseModel): name: str
class AnnouncementIn(BaseModel): title: str; body: str
class PasswordIn(BaseModel): current_password: str; new_password: str=Field(min_length=8)
class AttendanceIn(BaseModel): action: str

@app.on_event('startup')
def startup(): init_db()

@app.get('/',response_class=HTMLResponse)
def home(): return (ROOT/'frontend'/'index.html').read_text(encoding='utf-8')
@app.get('/api/health')
def health(): return {'status':'ok','app':'HCM Lite Pro','time':now_iso()}

@app.post('/api/auth/login')
def login(data:LoginIn):
    if data.role not in ('admin','hr','employee'): raise HTTPException(400,'Choose a valid role')
    with db() as c:
        u=c.execute('SELECT * FROM users WHERE lower(email)=lower(?) AND active=1',(data.email.strip(),)).fetchone()
        if not u or u['role']!=data.role or not verify_password(data.password,u['password_hash']): raise HTTPException(401,'Email, password, or selected role is incorrect')
        audit(c,u['id'],'login','user',u['id'])
        return {'access_token':token_for(dict(u)),'token_type':'bearer','user':public_user(dict(u))}
@app.post('/api/auth/face-login')
async def face_login(email: str = Form(...), password: str = Form(...), role: str = Form(...), photo: UploadFile = File(...)):
    """Credential + face verification login for employees and HR; successful verification marks today's check-in."""
    if role not in ('employee', 'hr'):
        raise HTTPException(400, 'Face login is only for HR and employees; admin uses email and password.')
    if photo.content_type not in ('image/jpeg', 'image/png', 'image/webp'):
        raise HTTPException(400, 'Upload a camera image in JPG, PNG or WEBP format')
    blob = await photo.read()
    if not blob or len(blob) > 5 * 1024 * 1024:
        raise HTTPException(413, 'Camera image is empty or exceeds 5 MB')
    with db() as c:
        row = c.execute('SELECT * FROM users WHERE lower(email)=lower(?) AND active=1', (email.strip(),)).fetchone()
        if not row or row['role'] != role or not verify_password(password, row['password_hash']):
            raise HTTPException(401, 'Email, password, or selected role is incorrect')
        if not row['employee_id']:
            raise HTTPException(400, 'This account has no employee profile linked')
        emp = c.execute('SELECT id, face_embedding, status, full_name FROM employees WHERE id=?', (row['employee_id'],)).fetchone()
        if not emp or emp['status'] != 'active':
            raise HTTPException(403, 'Employee profile is missing or inactive')
        if not emp['face_embedding']:
            msg = 'Your face is not enrolled. Ask Admin to enroll the HR face.' if role == 'hr' else 'Your face is not enrolled. Ask HR to enroll your face.'
            raise HTTPException(400, msg)
    import numpy as np
    observed = np.array(face_embedding(blob), dtype='float32')
    enrolled = np.array(json.loads(emp['face_embedding']), dtype='float32')
    score = float(np.dot(enrolled, observed))
    threshold = float(os.getenv('FACE_MATCH_THRESHOLD', '0.42'))
    if score < threshold:
        raise HTTPException(403, f'Face did not match your enrolled profile (similarity {score:.2f}). Try again in good lighting.')
    stamp = now_iso()
    local_now = datetime.now().astimezone()
    status = 'late' if local_now.time() > datetime.strptime('09:15', '%H:%M').time() else 'present'
    with db() as c:
        existing = c.execute('SELECT * FROM attendance WHERE employee_id=? AND work_date=?', (row['employee_id'], today())).fetchone()
        if existing and existing['check_in']:
            attendance_message = 'Face verified. You are already checked in today; dashboard access granted.'
            attendance_status = existing['status']
        else:
            if existing:
                c.execute('UPDATE attendance SET check_in=?,status=?,source=?,note=? WHERE id=?', (stamp, status, 'face-recognition-login', 'Face verified at login; image discarded', existing['id']))
            else:
                c.execute('INSERT INTO attendance(employee_id,work_date,check_in,status,source,note) VALUES (?,?,?,?,?,?)', (row['employee_id'], today(), stamp, status, 'face-recognition-login', 'Face verified at login; image discarded'))
            attendance_message = 'Face verified and attendance checked in. Dashboard access granted.'
            attendance_status = status
        audit(c, row['id'], 'face_login_check_in', 'attendance', row['employee_id'], {'similarity': round(score, 4), 'image_stored': False, 'role': role})
        audit(c, row['id'], 'login', 'user', row['id'], {'method': 'password+face'})
    return {'access_token': token_for(dict(row)), 'token_type': 'bearer', 'user': public_user(dict(row)), 'attendance': {'status': attendance_status, 'time': stamp, 'message': attendance_message}, 'similarity': round(score, 3)}

@app.get('/api/me')
def me(u=Depends(current_user)):
    with db() as c:
        emp=c.execute('SELECT e.*,d.name department FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE e.id=?',(u['employee_id'],)).fetchone() if u['employee_id'] else None
        return {'user':public_user(u),'employee':dict(emp) if emp else None}
@app.post('/api/auth/change-password')
def change_password(data:PasswordIn,u=Depends(current_user)):
    with db() as c:
        row=c.execute('SELECT password_hash FROM users WHERE id=?',(u['id'],)).fetchone()
        if not verify_password(data.current_password,row['password_hash']): raise HTTPException(400,'Current password is incorrect')
        c.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(data.new_password),u['id'])); audit(c,u['id'],'change_password','user',u['id'])
    return {'ok':True}

@app.get('/api/dashboard')
def dashboard(u=Depends(current_user)):
    with db() as c:
        ids=visible_employee_ids(c,u)
        if not ids: ids=[-1]
        marks=','.join('?' for _ in ids); emp_count=len(ids)
        present=c.execute(f"SELECT COUNT(*) n FROM attendance WHERE work_date=? AND employee_id IN ({marks}) AND status IN ('present','late','half_day')",[today(),*ids]).fetchone()['n']
        late=c.execute(f"SELECT COUNT(*) n FROM attendance WHERE work_date=? AND employee_id IN ({marks}) AND status='late'",[today(),*ids]).fetchone()['n']
        onleave=c.execute(f"SELECT COUNT(DISTINCT employee_id) n FROM leave_requests WHERE status='approved' AND start_date<=? AND end_date>=? AND employee_id IN ({marks})",[today(),today(),*ids]).fetchone()['n']
        pending=c.execute(f"SELECT COUNT(*) n FROM leave_requests WHERE status='pending' AND employee_id IN ({marks})",ids).fetchone()['n']
        payroll=c.execute(f"SELECT COALESCE(SUM(net),0) total FROM payroll WHERE month=? AND employee_id IN ({marks})",[date.today().strftime('%Y-%m'),*ids]).fetchone()['total']
        bydept=[dict(r) for r in c.execute(f"SELECT d.name department,COUNT(e.id) headcount FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE e.id IN ({marks}) AND e.status='active' GROUP BY d.id ORDER BY headcount DESC",ids)]
        trend=[]
        for n in range(6,-1,-1):
            day=(date.today()-timedelta(days=n)).isoformat()
            row=c.execute(f"SELECT COUNT(*) n FROM attendance WHERE work_date=? AND employee_id IN ({marks}) AND status IN ('present','late','half_day')",[day,*ids]).fetchone()
            trend.append({'date':day[5:],'present':row['n']})
        if u['role']=='employee':
            emp=c.execute('SELECT * FROM employees WHERE id=?',(u['employee_id'],)).fetchone()
            return {'scope':'personal','employee':dict(emp) if emp else None,'kpis':{'team_size':1,'present_today':present,'late_today':late,'pending_leaves':pending,'payroll_this_month':payroll},'department':bydept,'trend':trend}
        return {'scope':'company' if u['role']=='admin' else 'department','kpis':{'headcount':emp_count,'present_today':present,'late_today':late,'on_leave_today':onleave,'pending_leaves':pending,'payroll_this_month':payroll},'department':bydept,'trend':trend,'insights':[f'{late} late arrivals recorded today.',f'{pending} leave request(s) awaiting review.',f'{emp_count} employee record(s) in your data scope.']}

@app.get('/api/departments')
def departments(u=Depends(current_user)):
    with db() as c: return [dict(r) for r in c.execute('SELECT d.*,COUNT(e.id) headcount FROM departments d LEFT JOIN employees e ON e.department_id=d.id AND e.status="active" GROUP BY d.id ORDER BY d.name')]
@app.post('/api/departments')
def create_department(data:DepartmentIn,u=Depends(require('admin'))):
    with db() as c:
        try: cur=c.execute('INSERT INTO departments(name,created_at) VALUES (?,?)',(data.name.strip(),now_iso()))
        except sqlite3.IntegrityError: raise HTTPException(409,'Department already exists')
        audit(c,u['id'],'create','department',cur.lastrowid,{'name':data.name})
        return {'id':cur.lastrowid,'name':data.name}

@app.get('/api/employees')
def employees(q:str='',u=Depends(current_user)):
    with db() as c:
        ids=visible_employee_ids(c,u)
        if not ids: return []
        marks=','.join('?' for _ in ids); args=list(ids)
        sql=f'SELECT e.id,e.employee_code,e.full_name,e.email,e.department_id,d.name department,e.designation,e.hire_date,e.salary,e.status,e.manager_id,CASE WHEN e.face_embedding IS NULL THEN 0 ELSE 1 END face_enrolled FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE e.id IN ({marks})'
        if q: sql+=' AND (e.full_name LIKE ? OR e.email LIKE ? OR e.employee_code LIKE ?)'; args += [f'%{q}%']*3
        sql+=' ORDER BY e.id'
        return [dict(r) for r in c.execute(sql,args)]
@app.post('/api/employees')
def create_employee(data:EmployeeIn,u=Depends(require('admin','hr'))):
    with db() as c:
        if u['role']=='hr':
            own=c.execute('SELECT department_id FROM employees WHERE id=?',(u['employee_id'],)).fetchone()
            if not own or own['department_id']!=data.department_id: raise HTTPException(403,'HR can only hire into their own department')
        code='EMP'+secrets.token_hex(3).upper()
        try:
            cur=c.execute('INSERT INTO employees(employee_code,full_name,email,department_id,designation,hire_date,salary,created_at) VALUES (?,?,?,?,?,?,?,?)',(code,data.full_name,data.email,data.department_id,data.designation,data.hire_date,data.salary,now_iso()))
            eid=cur.lastrowid
            cur2=c.execute('INSERT INTO users(email,password_hash,role,employee_id,created_at) VALUES (?,?,?,?,?)',(data.email,hash_password(data.password),'employee',eid,now_iso()))
        except sqlite3.IntegrityError: raise HTTPException(409,'Email already exists or department is invalid')
        audit(c,u['id'],'create','employee',eid,{'code':code,'email':data.email})
        c.execute('INSERT INTO notifications(user_id,message,created_at) VALUES (?,?,?)',(cur2.lastrowid,'Your HCM Lite account has been created. Please sign in and change your password.',now_iso()))
        return {'id':eid,'employee_code':code,'email':data.email,'temporary_password':data.password}
@app.get('/api/hr-users')
def list_hr_users(u=Depends(require('admin'))):
    with db() as c:
        return [dict(r) for r in c.execute("SELECT u.id user_id,u.email,u.active,e.id employee_id,e.full_name,e.employee_code,e.department_id,d.name department,e.designation,e.hire_date FROM users u LEFT JOIN employees e ON e.id=u.employee_id LEFT JOIN departments d ON d.id=e.department_id WHERE u.role='hr' ORDER BY e.full_name")]

class HRIn(BaseModel):
    full_name: str = Field(min_length=2,max_length=120); email: str; department_id: int; designation: str='HR Manager'; hire_date: str=Field(default_factory=today); password: str=Field(min_length=8)

@app.post('/api/hr-users')
def create_hr_user(data:HRIn,u=Depends(require('admin'))):
    with db() as c:
        code='HR'+secrets.token_hex(3).upper()
        try:
            cur=c.execute('INSERT INTO employees(employee_code,full_name,email,department_id,designation,hire_date,salary,created_at) VALUES (?,?,?,?,?,?,?,?)',(code,data.full_name,data.email,data.department_id,data.designation,data.hire_date,0,now_iso()))
            eid=cur.lastrowid
            user_cur=c.execute('INSERT INTO users(email,password_hash,role,employee_id,created_at) VALUES (?,?,?,?,?)',(data.email,hash_password(data.password),'hr',eid,now_iso()))
        except sqlite3.IntegrityError: raise HTTPException(409,'Email already exists or department is invalid')
        audit(c,u['id'],'create','hr_user',user_cur.lastrowid,{'email':data.email,'department_id':data.department_id})
        return {'user_id':user_cur.lastrowid,'employee_id':eid,'employee_code':code,'email':data.email,'temporary_password':data.password}

@app.patch('/api/hr-users/{uid}/status')
def hr_user_status(uid:int,status:str,u=Depends(require('admin'))):
    if status not in ('active','inactive'): raise HTTPException(400,'Status must be active or inactive')
    with db() as c:
        row=c.execute("SELECT * FROM users WHERE id=? AND role='hr'",(uid,)).fetchone()
        if not row: raise HTTPException(404,'HR account not found')
        c.execute('UPDATE users SET active=? WHERE id=?',(1 if status=='active' else 0,uid))
        if row['employee_id']: c.execute('UPDATE employees SET status=? WHERE id=?',('active' if status=='active' else 'inactive',row['employee_id']))
        audit(c,u['id'],'update_status','hr_user',uid,{'status':status})
    return {'ok':True,'status':status}

@app.patch('/api/employees/{eid}/status')
def employee_status(eid:int,status:str,u=Depends(require('admin','hr'))):
    if status not in ('active','inactive','terminated'): raise HTTPException(400,'Invalid status')
    with db() as c:
        e=c.execute('SELECT * FROM employees WHERE id=?',(eid,)).fetchone()
        if not e: raise HTTPException(404,'Employee not found')
        linked=c.execute('SELECT role FROM users WHERE employee_id=?',(eid,)).fetchone()
        if u['role']=='hr' and linked and linked['role']!='employee': raise HTTPException(403,'HR cannot change HR/admin account status')
        if u['role']=='hr':
            own=c.execute('SELECT department_id FROM employees WHERE id=?',(u['employee_id'],)).fetchone()
            if not own or own['department_id']!=e['department_id']: raise HTTPException(403,'Outside your department')
        c.execute('UPDATE employees SET status=? WHERE id=?',(status,eid)); c.execute('UPDATE users SET active=? WHERE employee_id=?',(1 if status=='active' else 0,eid)); audit(c,u['id'],'update_status','employee',eid,{'status':status})
    return {'ok':True,'status':status}

@app.post('/api/attendance/{action}')
def attendance_action(action:str,data:AttendanceIn,u=Depends(require('employee'))):
    if action not in ('check-in','check-out') or data.action!=action: raise HTTPException(400,'Invalid attendance action')
    if not u['employee_id']: raise HTTPException(400,'Employee account is not linked to an employee record')
    with db() as c:
        e=c.execute('SELECT status FROM employees WHERE id=?',(u['employee_id'],)).fetchone()
        if not e or e['status']!='active': raise HTTPException(403,'Employee is not active')
        row=c.execute('SELECT * FROM attendance WHERE employee_id=? AND work_date=?',(u['employee_id'],today())).fetchone()
        now=datetime.now().astimezone(); stamp=now.isoformat(timespec='seconds')
        if action=='check-in':
            if row and row['check_in']: raise HTTPException(409,'You have already checked in today')
            status='late' if now.time()>datetime.strptime('09:15','%H:%M').time() else 'present'
            if row: c.execute('UPDATE attendance SET check_in=?,status=?,source=? WHERE id=?',(stamp,status,'web',row['id']))
            else: c.execute('INSERT INTO attendance(employee_id,work_date,check_in,status,source) VALUES (?,?,?,?,?)',(u['employee_id'],today(),stamp,status,'web'))
        else:
            if not row or not row['check_in']: raise HTTPException(400,'Check in first')
            if row['check_out']: raise HTTPException(409,'You have already checked out today')
            start=datetime.fromisoformat(row['check_in']); hours=(now-start).total_seconds()/3600
            status='half_day' if hours<5 else row['status']
            c.execute('UPDATE attendance SET check_out=?,status=? WHERE id=?',(stamp,status,row['id']))
        audit(c,u['id'],action,'attendance',u['employee_id'],{'source':'web'}); return {'ok':True,'action':action,'time':stamp,'status':status if action=='check-in' else c.execute('SELECT status FROM attendance WHERE employee_id=? AND work_date=?',(u['employee_id'],today())).fetchone()['status']}
@app.get('/api/attendance')
def attendance(date_from:str='',date_to:str='',u=Depends(current_user)):
    with db() as c:
        ids=visible_employee_ids(c,u)
        if not ids: return []
        marks=','.join('?' for _ in ids); args=list(ids); sql=f'SELECT a.*,e.full_name,e.employee_code,d.name department FROM attendance a JOIN employees e ON e.id=a.employee_id LEFT JOIN departments d ON d.id=e.department_id WHERE a.employee_id IN ({marks})'
        if date_from: sql+=' AND a.work_date>=?'; args.append(date_from)
        if date_to: sql+=' AND a.work_date<=?'; args.append(date_to)
        sql+=' ORDER BY a.work_date DESC,a.check_in DESC LIMIT 500'
        return [dict(r) for r in c.execute(sql,args)]

@app.get('/api/leave/types')
def leave_types(u=Depends(current_user)):
    with db() as c: return [dict(r) for r in c.execute('SELECT * FROM leave_types ORDER BY id')]
@app.get('/api/leaves')
def leaves(u=Depends(current_user)):
    with db() as c:
        ids=visible_employee_ids(c,u)
        if not ids: return []
        marks=','.join('?' for _ in ids)
        return [dict(r) for r in c.execute(f'SELECT l.*,e.full_name,e.employee_code,t.name leave_type FROM leave_requests l JOIN employees e ON e.id=l.employee_id JOIN leave_types t ON t.id=l.leave_type_id WHERE l.employee_id IN ({marks}) ORDER BY l.created_at DESC',ids)]
@app.post('/api/leaves')
def apply_leave(data:LeaveIn,u=Depends(current_user)):
    if u['role'] not in ('employee','hr'): raise HTTPException(403,'Not allowed')
    if not u['employee_id']: raise HTTPException(400,'Account not linked to employee')
    try: start=date.fromisoformat(data.start_date); end=date.fromisoformat(data.end_date)
    except ValueError: raise HTTPException(400,'Dates must use YYYY-MM-DD')
    if end<start: raise HTTPException(400,'End date must be on/after start date')
    days=(end-start).days+1
    with db() as c:
        overlap=c.execute("SELECT COUNT(*) n FROM leave_requests WHERE employee_id=? AND status IN ('pending','approved') AND NOT(end_date<? OR start_date>?)",(u['employee_id'],data.start_date,data.end_date)).fetchone()['n']
        if overlap: raise HTTPException(409,'Leave dates overlap an existing request')
        typ=c.execute('SELECT * FROM leave_types WHERE id=?',(data.leave_type_id,)).fetchone()
        if not typ: raise HTTPException(404,'Leave type not found')
        cur=c.execute('INSERT INTO leave_requests(employee_id,leave_type_id,start_date,end_date,days,reason,created_at) VALUES (?,?,?,?,?,?,?)',(u['employee_id'],data.leave_type_id,data.start_date,data.end_date,days,data.reason,now_iso()))
        audit(c,u['id'],'create','leave_request',cur.lastrowid,{'days':days}); return {'id':cur.lastrowid,'status':'pending','days':days}
@app.post('/api/leaves/{lid}/review')
def review_leave(lid:int,data:ReviewIn,u=Depends(require('admin','hr'))):
    if data.status not in ('approved','rejected'): raise HTTPException(400,'Status must be approved or rejected')
    with db() as c:
        row=c.execute('SELECT l.*,e.department_id FROM leave_requests l JOIN employees e ON e.id=l.employee_id WHERE l.id=?',(lid,)).fetchone()
        if not row: raise HTTPException(404,'Leave request not found')
        if u['role']=='hr':
            own=c.execute('SELECT department_id FROM employees WHERE id=?',(u['employee_id'],)).fetchone()
            if not own or own['department_id']!=row['department_id']: raise HTTPException(403,'Outside your department')
        if row['status']!='pending': raise HTTPException(409,'Request has already been reviewed')
        c.execute('UPDATE leave_requests SET status=?,reviewer_id=?,review_note=? WHERE id=?',(data.status,u['id'],data.review_note,lid)); audit(c,u['id'],'review','leave_request',lid,{'status':data.status})
        uid=c.execute('SELECT id FROM users WHERE employee_id=?',(row['employee_id'],)).fetchone()
        if uid: c.execute('INSERT INTO notifications(user_id,message,created_at) VALUES (?,?,?)',(uid['id'],f'Your leave request #{lid} was {data.status}.',now_iso()))
    return {'ok':True,'status':data.status}

@app.get('/api/payroll')
def get_payroll(month:str='',u=Depends(current_user)):
    month=month or date.today().strftime('%Y-%m')
    with db() as c:
        ids=visible_employee_ids(c,u)
        if not ids:return []
        marks=','.join('?' for _ in ids)
        return [dict(r) for r in c.execute(f'SELECT p.*,e.full_name,e.employee_code FROM payroll p JOIN employees e ON e.id=p.employee_id WHERE p.month=? AND p.employee_id IN ({marks}) ORDER BY e.full_name',[month,*ids])]
@app.post('/api/payroll/run')
def run_payroll(month:str=Form(...),u=Depends(require('admin','hr'))):
    try: datetime.strptime(month,'%Y-%m')
    except ValueError: raise HTTPException(400,'Month must be YYYY-MM')
    with db() as c:
        ids=visible_employee_ids(c,u)
        if not ids: raise HTTPException(400,'No employees in scope')
        count=0
        for eid in ids:
            e=c.execute('SELECT * FROM employees WHERE id=? AND status="active"',(eid,)).fetchone()
            if not e: continue
            existing=c.execute('SELECT finalized FROM payroll WHERE employee_id=? AND month=?',(eid,month)).fetchone()
            if existing and existing['finalized']: continue
            gross=float(e['salary'] or 0); tax=round(max(0,gross-50000)*0.05,2); deductions=0.0
            # Demo payroll calculation. Configure a locally reviewed statutory tax policy before real use.
            net=round(gross-tax-deductions,2)
            c.execute('INSERT INTO payroll(employee_id,month,gross,tax,deductions,net,created_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(employee_id,month) DO UPDATE SET gross=excluded.gross,tax=excluded.tax,deductions=excluded.deductions,net=excluded.net WHERE payroll.finalized=0',(eid,month,gross,tax,deductions,net,now_iso())); count+=1
        audit(c,u['id'],'run_payroll','payroll',month,{'records':count})
    return {'ok':True,'month':month,'records_processed':count,'note':'Demo tax calculation; verify local payroll law before real use.'}
@app.post('/api/payroll/finalize')
def finalize_payroll(month:str=Form(...),u=Depends(require('admin'))):
    with db() as c:
        c.execute('UPDATE payroll SET finalized=1 WHERE month=?',(month,)); audit(c,u['id'],'finalize_payroll','payroll',month)
    return {'ok':True,'month':month}
@app.get('/api/payroll/{pid}/payslip.pdf')
def payslip(pid:int,u=Depends(current_user)):
    with db() as c:
        row=c.execute('SELECT p.*,e.full_name,e.employee_code,e.email FROM payroll p JOIN employees e ON e.id=p.employee_id WHERE p.id=?',(pid,)).fetchone()
        if not row: raise HTTPException(404,'Payslip not found')
        if u['role']=='employee' and row['employee_id']!=u['employee_id']: raise HTTPException(403,'You can only download your own payslip')
        if u['role']=='hr' and row['employee_id'] not in visible_employee_ids(c,u): raise HTTPException(403,'Outside your department')
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    out=io.BytesIO(); p=canvas.Canvas(out,pagesize=A4); p.setTitle('HCM Lite Payslip')
    p.setFont('Helvetica-Bold',22); p.drawString(55,790,'HCM Lite Pro — Payslip')
    p.setFont('Helvetica',12); y=745
    for k,v in [('Employee',row['full_name']),('Employee code',row['employee_code']),('Pay period',row['month']),('Gross salary',f"PKR {row['gross']:,.2f}"),('Tax',f"PKR {row['tax']:,.2f}"),('Other deductions',f"PKR {row['deductions']:,.2f}"),('Net pay',f"PKR {row['net']:,.2f}"),('Status','Finalized' if row['finalized'] else 'Draft')]:
        p.drawString(60,y,str(k)); p.drawRightString(520,y,str(v)); y-=30
    p.setFont('Helvetica-Oblique',9); p.drawString(60,90,'Prototype payslip. Validate payroll policy and figures before official use.')
    p.showPage(); p.save(); out.seek(0)
    return StreamingResponse(out,media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename=payslip-{row["month"]}-{row["employee_code"]}.pdf'})

@app.get('/api/announcements')
def get_announcements(u=Depends(current_user)):
    with db() as c: return [dict(r) for r in c.execute('SELECT a.*,u.email author FROM announcements a LEFT JOIN users u ON u.id=a.author_id ORDER BY a.created_at DESC LIMIT 50')]
@app.post('/api/announcements')
def post_announcement(data:AnnouncementIn,u=Depends(require('admin','hr'))):
    with db() as c:
        cur=c.execute('INSERT INTO announcements(title,body,author_id,created_at) VALUES (?,?,?,?)',(data.title,data.body,u['id'],now_iso())); audit(c,u['id'],'create','announcement',cur.lastrowid)
        for row in c.execute('SELECT id FROM users WHERE active=1'): c.execute('INSERT INTO notifications(user_id,message,created_at) VALUES (?,?,?)',(row['id'],f'Announcement: {data.title}',now_iso()))
    return {'ok':True}
@app.get('/api/notifications')
def notifications(u=Depends(current_user)):
    with db() as c: return [dict(r) for r in c.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50',(u['id'],))]
@app.get('/api/audit')
def get_audit(u=Depends(require('admin'))):
    with db() as c: return [dict(r) for r in c.execute('SELECT a.*,u.email actor_email FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 300')]
@app.get('/api/leave/balance')
def leave_balance(u=Depends(current_user)):
    if not u['employee_id']: return []
    with db() as c:
        return [dict(r) for r in c.execute('SELECT t.id,t.name,t.annual_quota,t.paid,COALESCE(SUM(CASE WHEN l.status="approved" AND strftime("%Y",l.start_date)=? THEN l.days ELSE 0 END),0) used FROM leave_types t LEFT JOIN leave_requests l ON l.leave_type_id=t.id AND l.employee_id=? GROUP BY t.id',(str(date.today().year),u['employee_id']))]

# Face recognition: camera image is sent only for verification; raw frames are not persisted.
_face_session=None
def get_face_model():
    global _face_session
    if _face_session is not None: return _face_session
    try:
        import onnxruntime as ort
        from huggingface_hub import hf_hub_download
        repo=os.getenv('FACE_MODEL_REPO','garavv/arcface-onnx'); filename=os.getenv('FACE_MODEL_FILE','arc.onnx')
        path=hf_hub_download(repo_id=repo,filename=filename)
        _face_session=ort.InferenceSession(path,providers=['CPUExecutionProvider']); return _face_session
    except Exception as e: raise HTTPException(503,f'Face model could not load. Check internet/model access and try again. Detail: {str(e)[:180]}')
def face_embedding(image_bytes:bytes):
    import cv2, numpy as np
    arr=np.frombuffer(image_bytes,np.uint8); img=cv2.imdecode(arr,cv2.IMREAD_COLOR)
    if img is None: raise HTTPException(400,'Image could not be read')
    gray=cv2.cvtColor(img,cv2.COLOR_BGR2GRAY); detector=cv2.CascadeClassifier(cv2.data.haarcascades+'haarcascade_frontalface_default.xml')
    faces=detector.detectMultiScale(gray,scaleFactor=1.1,minNeighbors=5,minSize=(70,70))
    if len(faces)!=1: raise HTTPException(400,f'Exactly one detectable face is required; found {len(faces)}')
    x,y,w,h=faces[0]; crop=img[y:y+h,x:x+w]
    crop=cv2.cvtColor(cv2.resize(crop,(112,112)),cv2.COLOR_BGR2RGB).astype('float32')
    crop=(crop-127.5)/128.0
    sess=get_face_model(); inp=sess.get_inputs()[0]; out=sess.get_outputs()[0]
    # Model repos vary between NHWC and NCHW; infer expected layout from input shape.
    shape=inp.shape
    tensor=crop[None,...] if len(shape)==4 and shape[-1]==3 else crop.transpose(2,0,1)[None,...]
    emb=sess.run([out.name],{inp.name:tensor})[0].reshape(-1).astype('float32')
    emb=emb/(np.linalg.norm(emb)+1e-12)
    return emb.tolist()
@app.post('/api/face/enroll/{eid}')
async def face_enroll(eid:int,photo:UploadFile=File(...),u=Depends(require('admin','hr'))):
    if photo.content_type not in ('image/jpeg','image/png','image/webp'): raise HTTPException(400,'Upload a JPG, PNG or WEBP image')
    blob=await photo.read();
    if len(blob)>5*1024*1024: raise HTTPException(413,'Image must be under 5 MB')
    with db() as c:
        e=c.execute('SELECT * FROM employees WHERE id=?',(eid,)).fetchone()
        if not e: raise HTTPException(404,'Employee not found')
        linked=c.execute('SELECT role FROM users WHERE employee_id=?',(eid,)).fetchone()
        if u['role']=='hr' and linked and linked['role']!='employee': raise HTTPException(403,'HR cannot change HR/admin account status')
        if u['role']=='hr':
            own=c.execute('SELECT department_id FROM employees WHERE id=?',(u['employee_id'],)).fetchone()
            if not own or own['department_id']!=e['department_id']: raise HTTPException(403,'Outside your department')
    emb=face_embedding(blob)
    with db() as c: c.execute('UPDATE employees SET face_embedding=? WHERE id=?',(json.dumps(emb),eid)); audit(c,u['id'],'enroll_face','employee',eid,{'stored':'embedding only; image discarded'})
    return {'ok':True,'employee_id':eid,'message':'Face template enrolled. Original image was not stored.'}
@app.post('/api/face/attendance')
async def face_attendance(photo:UploadFile=File(...),u=Depends(require('employee'))):
    if not u['employee_id']: raise HTTPException(400,'No employee record linked to this account')
    if photo.content_type not in ('image/jpeg','image/png','image/webp'): raise HTTPException(400,'Upload a JPG, PNG or WEBP image')
    blob=await photo.read()
    if len(blob)>5*1024*1024: raise HTTPException(413,'Image must be under 5 MB')
    emb=face_embedding(blob)
    import numpy as np
    with db() as c:
        e=c.execute('SELECT face_embedding,status FROM employees WHERE id=?',(u['employee_id'],)).fetchone()
        if not e or not e['face_embedding']: raise HTTPException(400,'Your face is not enrolled yet. Ask HR to enroll your face first.')
        if e['status']!='active': raise HTTPException(403,'Employee is not active')
        enrolled=np.array(json.loads(e['face_embedding']),dtype='float32'); score=float(np.dot(enrolled,np.array(emb,dtype='float32')))
        threshold=float(os.getenv('FACE_MATCH_THRESHOLD','0.42'))
        if score<threshold: raise HTTPException(403,f'Face did not match your enrolled profile (similarity {score:.2f}). Try again or contact HR.')
        row=c.execute('SELECT * FROM attendance WHERE employee_id=? AND work_date=?',(u['employee_id'],today())).fetchone()
        stamp=now_iso(); now=datetime.now().astimezone()
        if row and row['check_in']:
            raise HTTPException(409,'Attendance already marked today. Use normal check-out if enabled.')
        status='late' if now.time()>datetime.strptime('09:15','%H:%M').time() else 'present'
        if row: c.execute('UPDATE attendance SET check_in=?,status=?,source=? WHERE id=?',(stamp,status,'face-recognition',row['id']))
        else: c.execute('INSERT INTO attendance(employee_id,work_date,check_in,status,source,note) VALUES (?,?,?,?,?,?)',(u['employee_id'],today(),stamp,status,'face-recognition','Face embedding matched; source frame discarded'))
        audit(c,u['id'],'face_check_in','attendance',u['employee_id'],{'similarity':round(score,4),'image_stored':False})
    return {'ok':True,'status':status,'time':stamp,'similarity':round(score,3),'message':'Face matched and check-in recorded. The uploaded frame was not saved.'}

@app.post('/api/ai/chat')
def ai_chat(message:str=Form(...),u=Depends(current_user)):
    # Data-grounded deterministic assistant fallback; no external LLM/key required.
    q=message.lower()
    with db() as c:
        ids=visible_employee_ids(c,u); marks=','.join('?' for _ in ids) or '?'; ids=ids or [-1]
        if any(x in q for x in ('headcount','how many employees','kitne employee','employees total')):
            n=c.execute(f'SELECT COUNT(*) n FROM employees WHERE id IN ({marks}) AND status="active"',ids).fetchone()['n']; answer=f'Your permitted scope has {n} active employee(s).'
        elif any(x in q for x in ('leave today','on leave','chhutti','leave par')):
            rows=c.execute(f'SELECT e.full_name,t.name leave_type FROM leave_requests l JOIN employees e ON e.id=l.employee_id JOIN leave_types t ON t.id=l.leave_type_id WHERE l.status="approved" AND l.start_date<=? AND l.end_date>=? AND l.employee_id IN ({marks})',[today(),today(),*ids]).fetchall()
            answer='Approved leave today: '+(', '.join(f"{r['full_name']} ({r['leave_type']})" for r in rows) if rows else 'none in your data scope.')
        elif any(x in q for x in ('late','latecomer','late arrival')):
            rows=c.execute(f'SELECT e.full_name,a.check_in FROM attendance a JOIN employees e ON e.id=a.employee_id WHERE a.work_date=? AND a.status="late" AND a.employee_id IN ({marks})',[today(),*ids]).fetchall()
            answer='Late arrivals today: '+(', '.join(f"{r['full_name']} at {r['check_in']}" for r in rows) if rows else 'none in your data scope.')
        elif any(x in q for x in ('policy','rule','attendance time','office time')): answer='Prototype policy: work starts at 09:00; arrivals after 09:15 are marked late. A shift shorter than 5 hours at check-out is marked half-day. Configure and review company rules before production.'
        elif any(x in q for x in ('salary','payroll','payslip')): answer='I can summarize payroll only for records in your role scope. Open Payroll to see the current month. Employees can only access their own payslips.'
        else: answer='I can answer data-backed questions about headcount, who is on approved leave today, late arrivals, attendance rules, and payroll navigation. Try: “Who is on leave today?”'
        audit(c,u['id'],'ai_query','assistant',None,{'query':message[:300]})
    return {'answer':answer,'mode':'data-grounded local assistant','scope':u['role']}

@app.get('/api/export/employees.csv')
def export_employees(u=Depends(require('admin','hr'))):
    import csv
    with db() as c:
        ids=visible_employee_ids(c,u); marks=','.join('?' for _ in ids) or '?'; ids=ids or [-1]
        rows=c.execute(f'SELECT e.employee_code,e.full_name,e.email,d.name department,e.designation,e.hire_date,e.salary,e.status FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE e.id IN ({marks})',ids).fetchall()
    def gen():
        out=io.StringIO(); w=csv.writer(out); w.writerow(['employee_code','full_name','email','department','designation','hire_date','salary','status']); yield out.getvalue(); out.seek(0); out.truncate(0)
        for r in rows: w.writerow(list(r)); yield out.getvalue(); out.seek(0); out.truncate(0)
    return StreamingResponse(gen(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=employees.csv'})
