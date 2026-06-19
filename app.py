"""BlackDev — студия сборок ReallyWorld. Flask single-file backend."""
import os, secrets, json, datetime as dt, hashlib, requests, io
from urllib.parse import urlencode
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for, session,
                   jsonify, send_from_directory, abort, flash)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         current_user, login_required)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)

app = Flask(__name__, instance_relative_config=False)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'blackdev-stable-secret-do-not-change-2026-rw'
app.config['PERMANENT_SESSION_LIFETIME'] = dt.timedelta(days=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = 'bd_sess'

db_url = os.getenv('DATABASE_URL', '').strip()
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)
if not db_url:
    db_url = 'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'blackdev.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

# Mail
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', '1') == '1'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', os.getenv('MAIL_USERNAME'))

db = SQLAlchemy(app)
mail = Mail(app)
login_mgr = LoginManager(app)
login_mgr.login_view = 'login'

MASTER_ADMIN_PASSWORD = 'oearh2026'  # неизменяемый, как просили

# ===================== ЗАЩИТА =====================
_login_attempts = {}  # ip -> [count, last_ts]

@app.before_request
def _security_gate():
    # блокировка перебора /admin/login
    if request.path == '/admin/login' and request.method == 'POST':
        ip = request.remote_addr or 'x'
        now = dt.datetime.utcnow().timestamp()
        cnt, ts = _login_attempts.get(ip, (0, now))
        if now - ts > 600: cnt = 0
        if cnt >= 6:
            abort(429)
        _login_attempts[ip] = (cnt+1, now)
    # запрет доступа к подозрительным путям (защита БД)
    blocked = ('/.env','/.git','/instance/','/blackdev.db','/wp-','/phpmyadmin','/.aws','/config.php')
    if any(b in request.path.lower() for b in blocked):
        abort(404)

@app.after_request
def _sec_headers(resp):
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive, nosnippet'
    resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return resp

@app.route('/robots.txt')
def _robots():
    return ("User-agent: *\nDisallow: /\n", 200, {'Content-Type':'text/plain'})

@app.route('/sitemap.xml')
def _sitemap(): abort(404)


@app.template_filter('from_json')
def _from_json(s):
    try: return json.loads(s) if s else []
    except: return []

# ===================== МОДЕЛИ =====================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    discord_id = db.Column(db.String(64), unique=True, nullable=True)
    google_id = db.Column(db.String(128), unique=True, nullable=True)
    avatar = db.Column(db.String(500))
    verified = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    def set_password(self, p): self.password_hash = generate_password_hash(p)
    def check_password(self, p): return self.password_hash and check_password_hash(self.password_hash, p)

class EmailCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    code = db.Column(db.String(8), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    purpose = db.Column(db.String(20), default='verify')  # verify | login

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product = db.Column(db.String(40), nullable=False)  # default | full | business
    rating = db.Column(db.Integer, default=5)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    user = db.relationship('User')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(40), unique=True, nullable=False)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, default=0.0)
    file_path = db.Column(db.String(500))  # выдаётся после покупки
    screenshots = db.Column(db.Text)  # JSON список путей

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    price = db.Column(db.Float)
    method = db.Column(db.String(30))  # balance | crypto | funpay | discord
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    product = db.relationship('Product')

class TopUpKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(40), unique=True, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    max_uses = db.Column(db.Integer, default=1)
    uses = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

class KeyRedemption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('top_up_key.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('key_id', 'user_id'),)

class Faq(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(300), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    sort = db.Column(db.Integer, default=0)

class Setting(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text)

# ===================== ХЕЛПЕРЫ =====================
def get_setting(k, default=''):
    s = Setting.query.get(k)
    return s.value if s else default

def set_setting(k, v):
    s = Setting.query.get(k)
    if s: s.value = v
    else: db.session.add(Setting(key=k, value=v))
    db.session.commit()

@login_mgr.user_loader
def load_user(uid): return User.query.get(int(uid))

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get('is_admin'): return redirect(url_for('admin_login'))
        return f(*a, **kw)
    return w

@app.context_processor
def inject_globals():
    products = Product.query.all() if db.inspect(db.engine).has_table('product') else []
    return dict(
        site_settings={s.key: s.value for s in Setting.query.all()} if db.inspect(db.engine).has_table('setting') else {},
        products=products,
        current_year=dt.datetime.utcnow().year,
    )

def allowed_image(fn): return '.' in fn and fn.rsplit('.', 1)[1].lower() in {'png','jpg','jpeg','gif','webp','svg'}

def save_upload(file_storage, prefix='img'):
    fn = secure_filename(file_storage.filename)
    ext = fn.rsplit('.', 1)[-1].lower() if '.' in fn else 'bin'
    new_name = f"{prefix}_{secrets.token_hex(8)}.{ext}"
    path = os.path.join(UPLOAD_DIR, new_name)
    file_storage.save(path)
    return '/static/uploads/' + new_name

def save_from_url(url, prefix='img'):
    r = requests.get(url, timeout=15, stream=True)
    r.raise_for_status()
    ext = url.rsplit('.', 1)[-1].split('?')[0].lower()
    if ext not in {'png','jpg','jpeg','gif','webp','svg'}: ext = 'jpg'
    new_name = f"{prefix}_{secrets.token_hex(8)}.{ext}"
    path = os.path.join(UPLOAD_DIR, new_name)
    with open(path, 'wb') as f:
        for chunk in r.iter_content(8192): f.write(chunk)
    return '/static/uploads/' + new_name

# ===================== ИНИЦИАЛИЗАЦИЯ =====================
def seed():
    if not Product.query.first():
        db.session.add_all([
            Product(slug='default', title='RW Default', description='Базовая сборка ReallyWorld. Чистая, стабильная, готова к запуску.', price=299, screenshots='[]'),
            Product(slug='full', title='RW Full', description='Полная сборка со всеми модулями, плагинами и кастомизацией.', price=799, screenshots='[]'),
            Product(slug='business', title='RW Business', description='Премиум-сборка для коммерческих проектов: антипираты, экономика, кастом-меню.', price=1499, screenshots='[]'),
        ])
    if not Faq.query.first():
        base = [
            ("Как происходит покупка?", "На сайте вы можете оплатить криптой через CryptoBot. Через Discord или FunPay — рублями. После оплаты сборка выдаётся автоматически в личном кабинете."),
            ("Какие способы оплаты доступны?", "Криптовалюта (BTC/USDT/TON и др.) на сайте, FunPay (рубли), Discord-сделка (рубли/крипта)."),
            ("Как получить сборку после оплаты?", "Заходите в Профиль → Мои покупки и скачивайте файл сборки."),
            ("Можно ли вернуть деньги?", "Возврат возможен только если сборка не была скачана."),
            ("Поддержка после покупки?", "Да, поддержка в нашем Discord — задавайте вопросы в тикете."),
            ("Чем отличается Default от Full?", "Default — базовая. Full — со всеми модулями и плагинами."),
            ("Что такое RW Business?", "Сборка для коммерческого запуска: 7 модулей, экономика, антипират, кастомное меню."),
            ("Можно ли пополнить баланс?", "Да, через ключи активации или прямой перевод (свяжитесь в Discord)."),
            ("Где взять ключ активации?", "Ключи раздаются на ивентах или у админов."),
            ("Безопасно ли покупать?", "Да. Все платежи проходят через CryptoBot/FunPay. Сборки уникальны и защищены."),
        ]
        for i, (q, a) in enumerate(base):
            db.session.add(Faq(question=q, answer=a, sort=i))
    defaults = {
        'site_title': 'BlackDev',
        'site_tagline': 'Студия сборок ReallyWorld',
        'discord_url': 'https://dsc.gg/blackdev',
        'telegram_url': 'https://t.me/blackdewvv',
        'funpay_url': '',
        'crypto_bot_url': '',
        'logo_url': '',
        'banner_url': '',
        'bg_url': '',
        'badge_url': '',
        'popup_image': '',
        'popup_enabled': '0',
        'effect': 'none',  # none | summer | newyear | halloween
        'accent_color': '#ffb02e',
        'accent_color_2': '#ff6a00',
    }
    for k, v in defaults.items():
        if not Setting.query.get(k):
            db.session.add(Setting(key=k, value=v))
    db.session.commit()

with app.app_context():
    db.create_all()
    seed()

# ===================== ПУБЛИЧНЫЕ СТРАНИЦЫ =====================
@app.route('/')
def index():
    reviews = Review.query.order_by(Review.created_at.desc()).limit(30).all()
    faqs = Faq.query.order_by(Faq.sort).all()
    return render_template('index.html', reviews=reviews, faqs=faqs)

@app.route('/api/reviews', methods=['POST'])
@login_required
def post_review():
    data = request.get_json(force=True)
    product = data.get('product')
    text = (data.get('text') or '').strip()[:1000]
    rating = max(1, min(5, int(data.get('rating', 5))))
    if product not in {'default', 'full', 'business'} or not text:
        return jsonify(error='bad input'), 400
    r = Review(user_id=current_user.id, product=product, rating=rating, text=text)
    db.session.add(r); db.session.commit()
    return jsonify(ok=True, id=r.id, user=current_user.username, avatar=current_user.avatar,
                   created=r.created_at.strftime('%Y-%m-%d %H:%M'), text=r.text,
                   rating=r.rating, product=r.product)

@app.route('/api/reviews')
def list_reviews():
    product = request.args.get('product')
    q = Review.query
    if product: q = q.filter_by(product=product)
    items = q.order_by(Review.created_at.desc()).limit(100).all()
    return jsonify([dict(id=r.id, user=r.user.username if r.user else 'guest',
                         avatar=r.user.avatar if r.user else '',
                         text=r.text, rating=r.rating, product=r.product,
                         created=r.created_at.strftime('%Y-%m-%d %H:%M')) for r in items])

# ===================== AUTH =====================
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        ident = request.form.get('ident','').strip()
        pwd = request.form.get('password','')
        u = User.query.filter((User.email==ident)|(User.username==ident)).first()
        if u and u.check_password(pwd):
            login_user(u, remember=True); return redirect(url_for('profile'))
        flash('Неверные данные', 'error')
    return render_template('auth/login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        username = request.form.get('username','').strip()
        pwd = request.form.get('password','')
        if not (email and username and len(pwd) >= 6):
            flash('Заполните все поля (пароль ≥ 6 символов)', 'error'); return redirect(url_for('register'))
        if User.query.filter((User.email==email)|(User.username==username)).first():
            flash('Email или ник уже заняты', 'error'); return redirect(url_for('register'))
        u = User(email=email, username=username); u.set_password(pwd)
        db.session.add(u); db.session.commit()
        # отправить код
        code = ''.join(secrets.choice('0123456789') for _ in range(6))
        db.session.add(EmailCode(email=email, code=code, purpose='verify')); db.session.commit()
        try:
            mail.send(Message('Код подтверждения BlackDev',
                              recipients=[email],
                              body=f'Ваш код подтверждения: {code}'))
        except Exception as e:
            app.logger.warning(f'mail fail: {e}')
        login_user(u, remember=True)
        return redirect(url_for('verify_email'))
    return render_template('auth/register.html')

@app.route('/verify', methods=['GET','POST'])
@login_required
def verify_email():
    if current_user.verified: return redirect(url_for('profile'))
    if request.method == 'POST':
        code = request.form.get('code','').strip()
        rec = EmailCode.query.filter_by(email=current_user.email, code=code, purpose='verify').first()
        if rec:
            current_user.verified = True
            db.session.delete(rec); db.session.commit()
            flash('Email подтверждён ✓', 'ok'); return redirect(url_for('profile'))
        flash('Код неверный', 'error')
    return render_template('auth/verify.html')

@app.route('/resend-code', methods=['POST'])
@login_required
def resend_code():
    if not current_user.email: return jsonify(error='no email'), 400
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    db.session.add(EmailCode(email=current_user.email, code=code, purpose='verify')); db.session.commit()
    try:
        mail.send(Message('Код подтверждения BlackDev', recipients=[current_user.email],
                          body=f'Ваш код подтверждения: {code}'))
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(ok=True)

@app.route('/logout')
def logout(): logout_user(); return redirect(url_for('index'))

# Discord OAuth
@app.route('/auth/discord')
def auth_discord():
    cid = os.getenv('DISCORD_CLIENT_ID'); ru = os.getenv('DISCORD_REDIRECT_URI')
    if not cid: return 'Discord OAuth не настроен', 500
    return redirect('https://discord.com/api/oauth2/authorize?' + urlencode(dict(
        client_id=cid, redirect_uri=ru, response_type='code', scope='identify email')))

@app.route('/auth/discord/callback')
def auth_discord_cb():
    code = request.args.get('code')
    if not code: return redirect(url_for('login'))
    r = requests.post('https://discord.com/api/oauth2/token', data=dict(
        client_id=os.getenv('DISCORD_CLIENT_ID'),
        client_secret=os.getenv('DISCORD_CLIENT_SECRET'),
        grant_type='authorization_code', code=code,
        redirect_uri=os.getenv('DISCORD_REDIRECT_URI')),
        headers={'Content-Type':'application/x-www-form-urlencoded'})
    tok = r.json().get('access_token')
    if not tok: return 'OAuth fail', 400
    u = requests.get('https://discord.com/api/users/@me',
                     headers={'Authorization': f'Bearer {tok}'}).json()
    user = User.query.filter_by(discord_id=u['id']).first()
    if not user:
        user = User(discord_id=u['id'], username='dc_'+u['username'][:60],
                    email=u.get('email'), verified=True,
                    avatar=f"https://cdn.discordapp.com/avatars/{u['id']}/{u.get('avatar')}.png" if u.get('avatar') else '')
        db.session.add(user); db.session.commit()
    login_user(user, remember=True); return redirect(url_for('profile'))

# Google OAuth (минимальный)
@app.route('/auth/google')
def auth_google():
    cid = os.getenv('GOOGLE_CLIENT_ID'); ru = os.getenv('GOOGLE_REDIRECT_URI')
    if not cid: return 'Google OAuth не настроен', 500
    return redirect('https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(dict(
        client_id=cid, redirect_uri=ru, response_type='code',
        scope='openid email profile', access_type='online')))

@app.route('/auth/google/callback')
def auth_google_cb():
    code = request.args.get('code')
    if not code: return redirect(url_for('login'))
    r = requests.post('https://oauth2.googleapis.com/token', data=dict(
        code=code, client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        redirect_uri=os.getenv('GOOGLE_REDIRECT_URI'),
        grant_type='authorization_code')).json()
    tok = r.get('access_token')
    if not tok: return 'OAuth fail', 400
    u = requests.get('https://www.googleapis.com/oauth2/v2/userinfo',
                     headers={'Authorization': f'Bearer {tok}'}).json()
    user = User.query.filter_by(google_id=u['id']).first()
    if not user:
        user = User(google_id=u['id'], username='g_'+(u.get('name','user')[:60]),
                    email=u.get('email'), verified=True, avatar=u.get('picture',''))
        db.session.add(user); db.session.commit()
    login_user(user, remember=True); return redirect(url_for('profile'))

# ===================== ПРОФИЛЬ И ПОКУПКИ =====================
@app.route('/profile')
@login_required
def profile():
    purchases = Purchase.query.filter_by(user_id=current_user.id).order_by(Purchase.created_at.desc()).all()
    return render_template('profile.html', purchases=purchases)

@app.route('/redeem', methods=['POST'])
@login_required
def redeem_key():
    code = request.form.get('code','').strip()
    k = TopUpKey.query.filter_by(code=code).first()
    if not k:
        flash('Ключ не найден', 'error'); return redirect(url_for('profile'))
    if k.uses >= k.max_uses:
        flash('Ключ исчерпан', 'error'); return redirect(url_for('profile'))
    if KeyRedemption.query.filter_by(key_id=k.id, user_id=current_user.id).first():
        flash('Вы уже активировали этот ключ', 'error'); return redirect(url_for('profile'))
    current_user.balance = (current_user.balance or 0) + k.amount
    k.uses += 1
    db.session.add(KeyRedemption(key_id=k.id, user_id=current_user.id))
    db.session.commit()
    flash(f'Баланс пополнен на {k.amount} ₽', 'ok')
    return redirect(url_for('profile'))

@app.route('/buy/<slug>', methods=['POST'])
@login_required
def buy(slug):
    p = Product.query.filter_by(slug=slug).first_or_404()
    method = request.form.get('method','balance')
    if method == 'balance':
        if (current_user.balance or 0) < p.price:
            flash('Недостаточно средств. Пополните баланс.', 'error'); return redirect(url_for('profile'))
        current_user.balance -= p.price
        db.session.add(Purchase(user_id=current_user.id, product_id=p.id, price=p.price, method='balance'))
        db.session.commit()
        flash('Сборка куплена! Скачайте её в профиле.', 'ok'); return redirect(url_for('profile'))
    # для криптобота/funpay/discord — направляем по ссылкам из настроек
    if method == 'crypto':
        url = get_setting('crypto_bot_url') or get_setting('discord_url')
    elif method == 'funpay':
        url = get_setting('funpay_url') or get_setting('discord_url')
    else:
        url = get_setting('discord_url')
    return redirect(url or url_for('index'))

@app.route('/download/<int:purchase_id>')
@login_required
def download(purchase_id):
    pur = Purchase.query.get_or_404(purchase_id)
    if pur.user_id != current_user.id: abort(403)
    if not pur.product.file_path: flash('Файл ещё не загружен админом', 'error'); return redirect(url_for('profile'))
    path = pur.product.file_path
    if path.startswith('/static/'): path = path[1:]
    return send_from_directory(BASE_DIR, path, as_attachment=True)

# ===================== АДМИНКА =====================
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        p = request.form.get('password','')
        secondary = os.getenv('ADMIN_SECONDARY_PASSWORD', '2LPTEWodJq9_Mtpw')
        if p == MASTER_ADMIN_PASSWORD or p == secondary:
            session.permanent = True
            session['is_admin'] = True
            session['admin_ip'] = request.remote_addr
            return redirect(url_for('admin_dash'))
        flash('Неверный пароль', 'error')
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout(): session.pop('is_admin', None); return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin_dash():
    stats = dict(
        users=User.query.count(),
        reviews=Review.query.count(),
        purchases=Purchase.query.count(),
        revenue=db.session.query(db.func.sum(Purchase.price)).scalar() or 0,
    )
    return render_template('admin/dashboard.html', stats=stats)

@app.route('/admin/settings', methods=['GET','POST'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        for key in ['site_title','site_tagline','discord_url','telegram_url','funpay_url',
                    'crypto_bot_url','effect','accent_color','accent_color_2','popup_enabled']:
            if key in request.form: set_setting(key, request.form[key])
        # картинки: файл или url
        for field in ['logo_url','banner_url','bg_url','badge_url','popup_image']:
            file = request.files.get(field + '_file')
            url = request.form.get(field + '_url_input','').strip()
            if file and file.filename:
                set_setting(field, save_upload(file, prefix=field))
            elif url:
                if url.startswith('http'):
                    try: set_setting(field, save_from_url(url, prefix=field))
                    except Exception as e: flash(f'{field}: {e}', 'error')
                else:
                    set_setting(field, url)
        flash('Настройки сохранены', 'ok')
        return redirect(url_for('admin_settings'))
    return render_template('admin/settings.html')

@app.route('/admin/users')
@admin_required
def admin_users():
    q = request.args.get('q','').strip()
    users = User.query
    if q:
        like = f'%{q}%'
        users = users.filter((User.username.ilike(like))|(User.email.ilike(like)))
    return render_template('admin/users.html', users=users.order_by(User.id.desc()).limit(500).all(), q=q)

@app.route('/admin/users/<int:uid>/balance', methods=['POST'])
@admin_required
def admin_set_balance(uid):
    u = User.query.get_or_404(uid)
    u.balance = float(request.form.get('balance', 0))
    db.session.commit()
    flash('Баланс обновлён', 'ok')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@admin_required
def admin_del_user(uid):
    User.query.filter_by(id=uid).delete(); db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/reviews')
@admin_required
def admin_reviews():
    q = request.args.get('q','').strip()
    rev = Review.query
    if q: rev = rev.filter(Review.text.ilike(f'%{q}%'))
    return render_template('admin/reviews.html', reviews=rev.order_by(Review.created_at.desc()).limit(500).all(), q=q)

@app.route('/admin/reviews/<int:rid>/delete', methods=['POST'])
@admin_required
def admin_del_review(rid):
    Review.query.filter_by(id=rid).delete(); db.session.commit()
    return redirect(url_for('admin_reviews'))

@app.route('/admin/products', methods=['GET','POST'])
@admin_required
def admin_products():
    if request.method == 'POST':
        pid = int(request.form.get('id'))
        p = Product.query.get_or_404(pid)
        p.title = request.form.get('title', p.title)
        p.description = request.form.get('description', p.description)
        p.price = float(request.form.get('price', p.price))
        # файл сборки
        f = request.files.get('build_file')
        if f and f.filename:
            fn = secure_filename(f.filename)
            ext = fn.rsplit('.',1)[-1] if '.' in fn else 'zip'
            name = f'build_{p.slug}_{secrets.token_hex(6)}.{ext}'
            f.save(os.path.join(UPLOAD_DIR, name))
            p.file_path = '/static/uploads/' + name
        # скриншоты — несколько файлов или ссылок (по строкам)
        shots = json.loads(p.screenshots or '[]')
        for f in request.files.getlist('screenshots'):
            if f and f.filename and allowed_image(f.filename):
                shots.append(save_upload(f, prefix='shot'))
        for url in (request.form.get('screenshot_urls','') or '').splitlines():
            url = url.strip()
            if url.startswith('http'):
                try: shots.append(save_from_url(url, prefix='shot'))
                except Exception as e: flash(f'url err: {e}', 'error')
        p.screenshots = json.dumps(shots)
        db.session.commit()
        flash('Сохранено', 'ok')
        return redirect(url_for('admin_products'))
    return render_template('admin/products.html', products=Product.query.all())

@app.route('/admin/products/<int:pid>/shot/<int:idx>/delete', methods=['POST'])
@admin_required
def admin_del_shot(pid, idx):
    p = Product.query.get_or_404(pid)
    shots = json.loads(p.screenshots or '[]')
    if 0 <= idx < len(shots): shots.pop(idx)
    p.screenshots = json.dumps(shots); db.session.commit()
    return redirect(url_for('admin_products'))

@app.route('/admin/keys', methods=['GET','POST'])
@admin_required
def admin_keys():
    if request.method == 'POST':
        amount = float(request.form.get('amount', 0))
        uses = int(request.form.get('uses', 1))
        code = request.form.get('code','').strip() or secrets.token_urlsafe(10)
        if TopUpKey.query.filter_by(code=code).first():
            flash('Такой ключ уже существует', 'error')
        else:
            db.session.add(TopUpKey(code=code, amount=amount, max_uses=uses)); db.session.commit()
            flash(f'Ключ создан: {code}', 'ok')
        return redirect(url_for('admin_keys'))
    return render_template('admin/keys.html', keys=TopUpKey.query.order_by(TopUpKey.id.desc()).all())

@app.route('/admin/keys/<int:kid>/delete', methods=['POST'])
@admin_required
def admin_del_key(kid):
    TopUpKey.query.filter_by(id=kid).delete(); db.session.commit()
    return redirect(url_for('admin_keys'))

@app.route('/admin/faq', methods=['GET','POST'])
@admin_required
def admin_faq():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            db.session.add(Faq(question=request.form['question'], answer=request.form['answer'],
                               sort=int(request.form.get('sort', 0))))
        elif action == 'edit':
            f = Faq.query.get_or_404(int(request.form['id']))
            f.question = request.form['question']; f.answer = request.form['answer']
            f.sort = int(request.form.get('sort', 0))
        elif action == 'del':
            Faq.query.filter_by(id=int(request.form['id'])).delete()
        db.session.commit()
        return redirect(url_for('admin_faq'))
    return render_template('admin/faq.html', faqs=Faq.query.order_by(Faq.sort).all())

@app.errorhandler(404)
def nf(e): return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT','5000')), debug=True)
