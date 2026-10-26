import csv
import io
import json
import math
import secrets
import sqlite3
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from .core import identify, similarity, StabilityGate
from .store import Store, now_iso
from .vision import FaceEngine


def text(value, label, maximum=120):
    if not isinstance(value,str) or not value.strip() or len(value.strip()) > maximum:
        raise ValueError(f"أدخل {label} بشكل صحيح (حتى {maximum} حرفًا)")
    return value.strip()


def integer(value, label, low=1, high=2_000_000_000):
    if isinstance(value,bool):
        raise ValueError(f"{label} غير صالح")
    try:
        result = int(value)
        if str(result) != str(value) or not low <= result <= high:
            raise ValueError()
        return result
    except (ValueError,TypeError):
        raise ValueError(f"{label} غير صالح") from None


def create_app(root, data_dir, engine=None):
    root,data_dir = Path(root),Path(data_dir)
    data_dir.mkdir(parents=True,exist_ok=True)
    secret_file = data_dir / 'session.key'
    if not secret_file.exists():
        try:
            with secret_file.open('x') as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    app = Flask(__name__,static_folder=str(root/'static'),static_url_path='/static')
    app.config.update(SECRET_KEY=secret_file.read_text().strip(), MAX_CONTENT_LENGTH=8*1024*1024,
                      SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=8),TRUSTED_HOSTS=['localhost','127.0.0.1'])
    store = Store(data_dir/'basira.sqlite3')
    engine = engine or FaceEngine(root/'models')
    gate,gate_lock = StabilityGate(),threading.Lock()
    attempts,login_lock = {},threading.Lock()
    app.extensions.update(basira_store=store,basira_engine=engine,basira_gate=gate)
    try:
        engine.load()
    except ValueError:
        pass

    @app.before_request
    def protect():
        if request.path.startswith('/api/'):
            session.setdefault('csrf',secrets.token_hex(24))
            if request.method == 'POST':
                if not request.is_json:
                    return jsonify(error='الطلب يجب أن يكون JSON'),415
                if not secrets.compare_digest(request.headers.get('X-CSRF-Token',''),session['csrf']):
                    return jsonify(error='انتهت صلاحية الصفحة؛ أعد تحميلها'),403
                if not isinstance(request.get_json(silent=True),dict):
                    return jsonify(error='بيانات الطلب غير صالحة'),400
            if request.path not in ('/api/state','/api/login','/api/setup') and not session.get('admin'):
                return jsonify(error='سجّل الدخول أولًا'),401

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Permissions-Policy'] = 'camera=(self), microphone=()'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(error=str(exc)),400

    @app.errorhandler(sqlite3.IntegrityError)
    def conflict(exc):
        return jsonify(error='الرقم أو الاسم موجود مسبقًا، أو أن السجل مرتبط ببيانات أخرى'),409

    @app.errorhandler(HTTPException)
    def http_error(exc):
        if request.path.startswith('/api/'):
            return jsonify(error={413:'حجم الصور كبير جدًا',404:'السجل أو المسار غير موجود',400:'الطلب غير صالح'}.get(exc.code,'تعذّر تنفيذ الطلب')),exc.code
        return exc

    @app.errorhandler(Exception)
    def unexpected(exc):
        app.logger.exception('Unexpected error')
        return jsonify(error='حدث خطأ داخلي. راجع نافذة تشغيل البرنامج'),500

    @app.get('/')
    def index():
        return app.send_static_file('index.html')

    @app.get('/api/state')
    def state():
        admin = store.one('SELECT id,name FROM admins LIMIT 1')
        return jsonify(setup=bool(admin), authenticated=bool(session.get('admin')),
                       admin_name=admin['name'] if admin and session.get('admin') else '',
                       csrf=session['csrf'],engine=engine.status())

    @app.post('/api/setup')
    def setup():
        body = request.json
        name,password = text(body.get('name'),'اسم المدير'),text(body.get('password'),'كلمة المرور',256)
        if len(password) < 10:
            raise ValueError('كلمة المرور يجب أن تتكون من 10 أحرف على الأقل')
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM admins').fetchone():
                raise ValueError('تم إنشاء حساب المدير بالفعل')
            db.execute('INSERT INTO admins(id,name,password) VALUES(1,?,?)', (name,generate_password_hash(password,method='pbkdf2:sha256:600000')))
            store.audit(db,'admin_setup','تم إنشاء حساب المدير')
        session.clear()
        session.update(admin=1,csrf=secrets.token_hex(24),camera=secrets.token_hex(16))
        session.permanent=True
        return jsonify(ok=True,csrf=session['csrf'])

    @app.post('/api/login')
    def login():
        password=text(request.json.get('password'),'كلمة المرور',256)
        with login_lock:
            count,until=attempts.get('local',(0,0))
            if until > time.monotonic():
                return jsonify(error='انتظر دقيقة قبل المحاولة مجددًا'),429
            admin=store.one('SELECT * FROM admins LIMIT 1')
            if not admin or not check_password_hash(admin['password'],password):
                count+=1
                attempts['local']=(count,time.monotonic()+60 if count>=5 else 0)
                return jsonify(error='كلمة المرور غير صحيحة'),401
            attempts.clear()
        session.clear()
        session.update(admin=admin['id'],csrf=secrets.token_hex(24),camera=secrets.token_hex(16))
        session.permanent=True
        return jsonify(ok=True,csrf=session['csrf'])

    @app.post('/api/logout')
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.post('/api/password')
    def password_change():
        body=request.json
        admin=store.one('SELECT * FROM admins WHERE id=?',(session['admin'],))
        if not check_password_hash(admin['password'],str(body.get('current',''))):
            raise ValueError('كلمة المرور الحالية غير صحيحة')
        password=text(body.get('password'),'كلمة المرور الجديدة',256)
        if len(password)<10:
            raise ValueError('استخدم 10 أحرف على الأقل')
        with store.connect() as db:
            db.execute('UPDATE admins SET password=? WHERE id=?',(generate_password_hash(password,method='pbkdf2:sha256:600000'),admin['id']))
            store.audit(db,'password_change','تم تغيير كلمة مرور المدير')
        return jsonify(ok=True)

    @app.get('/api/dashboard')
    def dashboard():
        people=store.one('SELECT COUNT(*) n FROM persons WHERE active=1')['n']
        today=now_iso()[:10]
        return jsonify(people=people,groups=store.one('SELECT COUNT(*) n FROM groups')['n'],
            today=store.one('SELECT COUNT(*) n FROM attendance WHERE substr(recorded_at,1,10)=?',(today,))['n'],
            open_sessions=store.one('SELECT COUNT(*) n FROM sessions WHERE closed_at IS NULL')['n'],engine=engine.status(),
            recent=store.rows('SELECT a.recorded_at,a.status,p.name,p.code,s.title FROM attendance a JOIN persons p ON p.id=a.person_id JOIN sessions s ON s.id=a.session_id ORDER BY a.id DESC LIMIT 8'))

    @app.get('/api/groups')
    def groups():
        return jsonify(store.rows('SELECT g.*,COUNT(p.id) people FROM groups g LEFT JOIN persons p ON p.group_id=g.id AND p.active=1 GROUP BY g.id ORDER BY g.name'))

    @app.post('/api/groups')
    def add_group():
        name=text(request.json.get('name'),'اسم المجموعة',80)
        with store.connect() as db:
            cursor=db.execute('INSERT INTO groups(name) VALUES(?)',(name,))
            store.audit(db,'group_add',name)
        return jsonify(id=cursor.lastrowid)

    @app.get('/api/persons')
    def persons():
        return jsonify(store.rows('SELECT p.*,g.name group_name,(SELECT COUNT(*) FROM samples s WHERE s.person_id=p.id) samples FROM persons p JOIN groups g ON g.id=p.group_id ORDER BY p.id DESC'))

    def enrollment_features(body,exclude=None):
        frames=body.get('frames')
        if body.get('consent') is not True:
            raise ValueError('يلزم توثيق موافقة الشخص على تسجيل بيانات وجهه')
        if not isinstance(frames,list) or not 3<=len(frames)<=5 or not all(isinstance(f,str) for f in frames) or len(set(frames))<3:
            raise ValueError('التقط 3 صور مختلفة على الأقل للشخص نفسه')
        features=[]
        candidates=store.candidates(exclude=exclude)
        for frame in frames:
            result=engine.extract(frame)
            feature=result.get('feature')
            if feature is None:
                raise ValueError(result['message'])
            if features and similarity(feature,features[0]) < 0.55:
                raise ValueError('صور التسجيل غير متطابقة بما يكفي؛ أعد التصوير للشخص نفسه')
            duplicate,_=identify(feature,candidates,threshold=0.50,margin=0.0)
            if duplicate is not None:
                raise ValueError('هذا الوجه قريب من شخص مسجّل بالفعل؛ راجع السجل قبل الإضافة')
            features.append(feature)
        return features

    @app.post('/api/persons')
    def add_person():
        body=request.json
        name,code=text(body.get('name'),'الاسم'),text(body.get('code'),'الرقم',40)
        group_id=integer(body.get('group_id'),'المجموعة')
        if not store.one('SELECT id FROM groups WHERE id=?',(group_id,)):
            raise ValueError('اختر مجموعة موجودة')
        features=enrollment_features(body)
        with store.connect() as db:
            cursor=db.execute('INSERT INTO persons(code,name,group_id,consent_at,created_at) VALUES(?,?,?,?,?)',(code,name,group_id,now_iso(),now_iso()))
            person_id=cursor.lastrowid
            db.executemany('INSERT INTO samples(person_id,feature) VALUES(?,?)',[(person_id,json.dumps(f)) for f in features])
            store.audit(db,'person_add',f'person={person_id};code={code}')
        return jsonify(id=person_id)

    @app.post('/api/persons/<int:person_id>/update')
    def update_person(person_id):
        body=request.json
        person=store.one('SELECT * FROM persons WHERE id=?',(person_id,))
        if not person:
            raise ValueError('الشخص غير موجود')
        name,code=text(body.get('name'),'الاسم'),text(body.get('code'),'الرقم',40)
        if not isinstance(body.get('active'),bool):
            raise ValueError('حالة الشخص غير صالحة')
        with store.connect() as db:
            db.execute('UPDATE persons SET name=?,code=?,active=? WHERE id=?',(name,code,int(body['active']),person_id))
            store.audit(db,'person_update',f'person={person_id};active={body["active"]}')
        return jsonify(ok=True)

    @app.post('/api/persons/<int:person_id>/erase-face')
    def erase_face(person_id):
        with store.connect() as db:
            db.execute('DELETE FROM samples WHERE person_id=?',(person_id,))
            store.audit(db,'face_erased',f'person={person_id}')
        return jsonify(ok=True)

    @app.post('/api/persons/<int:person_id>/enroll')
    def enroll_again(person_id):
        if not store.one('SELECT id FROM persons WHERE id=?',(person_id,)):
            raise ValueError('الشخص غير موجود')
        features=enrollment_features(request.json,exclude=person_id)
        with store.connect() as db:
            db.execute('DELETE FROM samples WHERE person_id=?',(person_id,))
            db.executemany('INSERT INTO samples(person_id,feature) VALUES(?,?)',[(person_id,json.dumps(f)) for f in features])
            db.execute('UPDATE persons SET consent_at=? WHERE id=?',(now_iso(),person_id))
            store.audit(db,'face_renewed',f'person={person_id}')
        return jsonify(ok=True)

    @app.get('/api/sessions')
    def sessions():
        return jsonify(store.rows('''SELECT s.*,g.name group_name,
            (SELECT COUNT(*) FROM roster r WHERE r.session_id=s.id) total,
            (SELECT COUNT(*) FROM attendance a WHERE a.session_id=s.id) attended
            FROM sessions s JOIN groups g ON g.id=s.group_id ORDER BY s.id DESC'''))

    @app.post('/api/sessions')
    def add_session():
        body=request.json
        title=text(body.get('title'),'عنوان الجلسة')
        group_id=integer(body.get('group_id'),'المجموعة')
        late=integer(body.get('late_minutes',15),'دقائق التأخير',0,240)
        with store.connect() as db:
            if not db.execute('SELECT 1 FROM groups WHERE id=?',(group_id,)).fetchone():
                raise ValueError('المجموعة غير موجودة')
            if not db.execute('SELECT 1 FROM persons WHERE group_id=? AND active=1',(group_id,)).fetchone():
                raise ValueError('أضف أشخاصًا نشطين للمجموعة أولًا')
            cursor=db.execute('INSERT INTO sessions(title,group_id,started_at,late_minutes) VALUES(?,?,?,?)',(title,group_id,now_iso(),late))
            sid=cursor.lastrowid
            db.execute('INSERT INTO roster(session_id,person_id) SELECT ?,id FROM persons WHERE group_id=? AND active=1',(sid,group_id))
            store.audit(db,'session_open',f'session={sid};title={title}')
        return jsonify(id=sid)

    @app.post('/api/sessions/<int:sid>/close')
    def close_session(sid):
        with store.connect() as db:
            db.execute('UPDATE sessions SET closed_at=? WHERE id=? AND closed_at IS NULL',(now_iso(),sid))
            store.audit(db,'session_close',f'session={sid}')
        return jsonify(ok=True)

    @app.post('/api/recognize')
    def recognize():
        body=request.json
        sid=integer(body.get('session_id'),'الجلسة')
        current=store.one('SELECT id FROM sessions WHERE id=? AND closed_at IS NULL',(sid,))
        if not current:
            raise ValueError('اختر جلسة مفتوحة')
        result=engine.extract(body.get('image'))
        feature=result.pop('feature',None)
        threshold=float(store.one("SELECT value FROM settings WHERE key='threshold'")['value'])
        # Match against all active identities before checking the roster, so a
        # person outside the class is not forced into its smaller candidate set.
        person_id,score=identify(feature,store.candidates(),threshold) if feature else (None,0.0)
        member=store.one('SELECT 1 FROM roster WHERE session_id=? AND person_id=?',(sid,person_id)) if person_id else None
        key=(session['camera'],sid)
        with gate_lock:
            count,stable=gate.observe(key,person_id if member else None)
        result.update(progress=count,required=gate.required,similarity=round(score,4),recognized=False)
        if person_id and not member:
            result['message']='الشخص ليس ضمن قائمة هذه الجلسة'
        elif person_id:
            person=store.one('SELECT name,code FROM persons WHERE id=?',(person_id,))
            result.update(person=person,recognized=True)
            result['message']=f"تمت المطابقة: {person['name']} — جاري التحقق ({count}/{gate.required})"
            if stable:
                attendance,created=store.record(sid,person_id,'face',score)
                result.update(recorded=True,created=created,status=attendance['status'])
                result['message']='تم تسجيل الحضور' if created else 'الحضور مسجّل بالفعل لهذه الجلسة'
        elif feature:
            result['message']='وجه غير مسجّل أو المطابقة غير مؤكدة'
        return jsonify(result)

    @app.get('/api/reports/<int:sid>')
    def report(sid):
        current=store.one('SELECT s.*,g.name group_name FROM sessions s JOIN groups g ON g.id=s.group_id WHERE s.id=?',(sid,))
        if not current:
            raise ValueError('الجلسة غير موجودة')
        return jsonify(session=current,rows=store.report(sid))

    @app.post('/api/manual')
    def manual():
        body=request.json
        reason=text(body.get('reason'),'سبب التسجيل اليدوي',250)
        row,created=store.record(integer(body.get('session_id'),'الجلسة'),integer(body.get('person_id'),'الشخص'),'manual',reason=reason)
        return jsonify(record=row,created=created)

    @app.post('/api/attendance/<int:aid>/remove')
    def remove_attendance(aid):
        reason=text(request.json.get('reason'),'سبب التصحيح',250)
        with store.connect() as db:
            row=db.execute('SELECT * FROM attendance WHERE id=?',(aid,)).fetchone()
            if not row:
                raise ValueError('سجل الحضور غير موجود')
            db.execute('DELETE FROM attendance WHERE id=?',(aid,))
            store.audit(db,'attendance_remove',json.dumps({'record':dict(row),'reason':reason},ensure_ascii=False))
        return jsonify(ok=True)

    @app.get('/api/reports/<int:sid>/csv')
    def report_csv(sid):
        if not store.one('SELECT id FROM sessions WHERE id=?',(sid,)):
            raise ValueError('الجلسة غير موجودة')
        output=io.StringIO(newline='')
        writer=csv.writer(output)
        writer.writerow(['الرقم','الاسم','المجموعة','الحالة','وقت التسجيل','الطريقة','درجة التشابه'])
        labels={'present':'حاضر','late':'متأخر','absent':'غائب','face':'الوجه','manual':'يدوي'}
        def safe(value):
            value=str(value or '')
            return "'"+value if value.lstrip().startswith(('=','+','-','@','\t','\r')) else value
        for row in store.report(sid):
            writer.writerow([safe(row['code']),safe(row['name']),safe(row['group_name']),labels[row['status']],row['recorded_at'] or '',labels.get(row['method'],''),row['score'] if row['score'] is not None else ''])
        return send_file(io.BytesIO(output.getvalue().encode('utf-8-sig')),mimetype='text/csv; charset=utf-8',as_attachment=True,download_name=f'Attendance_{sid}.csv')

    @app.get('/api/settings')
    def settings():
        return jsonify(threshold=float(store.one("SELECT value FROM settings WHERE key='threshold'")['value']),engine=engine.status())

    @app.post('/api/settings')
    def save_settings():
        try:
            threshold=float(request.json.get('threshold'))
        except (TypeError,ValueError):
            raise ValueError('درجة المطابقة غير صالحة') from None
        if not math.isfinite(threshold) or not 0.40<=threshold<=0.85:
            raise ValueError('درجة المطابقة يجب أن تكون بين 0.40 و0.85')
        with store.connect() as db:
            db.execute("UPDATE settings SET value=? WHERE key='threshold'",(str(threshold),))
            store.audit(db,'threshold_change',str(threshold))
        with gate_lock:
            gate.states.clear()
        return jsonify(ok=True)

    @app.get('/api/audit')
    def audit():
        return jsonify(store.rows('SELECT * FROM audit ORDER BY id DESC LIMIT 150'))

    @app.get('/api/backup')
    def backup():
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'basira.sqlite3'
            store.backup(target)
            content=target.read_bytes()
        with store.connect() as db:
            store.audit(db,'backup','تم إنشاء نسخة احتياطية')
        return send_file(io.BytesIO(content),mimetype='application/octet-stream',as_attachment=True,download_name=f'Basira_Backup_{now_iso()[:10]}.sqlite3')

    return app
