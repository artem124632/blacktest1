# BlackDev — студия сборок ReallyWorld

Flask-сайт с админкой, авторизацией, балансом, отзывами, FAQ, эффектами и админ-настройкой картинок/баннеров. Готов к деплою на **Railway**.

## 🚀 Локальный запуск

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # отредактируйте при необходимости
python app.py
```

Сайт: http://localhost:5000
Админка: http://localhost:5000/admin

## 🔑 Пароли админки

- **`oearh2026`** — мастер-пароль (захардкожен, изменить нельзя)
- **`2LPTEWodJq9_Mtpw`** — второй пароль (можно поменять в `.env` через `ADMIN_SECONDARY_PASSWORD`)

## 🛤 Деплой на Railway

1. Создайте проект на [railway.app](https://railway.app), подключите GitHub-репо или загрузите через CLI (`railway up`).
2. Добавьте сервис **PostgreSQL** — `DATABASE_URL` подставится автоматически.
3. В **Variables** добавьте переменные из `.env.example` (SECRET_KEY, MAIL_*, опционально DISCORD/GOOGLE OAuth).
4. Railway сам обнаружит Python, поставит `requirements.txt` и запустит `Procfile`.

## ⚙ Что можно настроить через админку

- **Настройки сайта**: название, слоган, цвета, ссылки на Discord/Telegram/FunPay/CryptoBot, эффект частиц (лето/новый год/хэллоуин), включение попапа.
- **Картинки** (загрузка файлом или ссылкой): логотип, бейдж, баннер главной, фон сайта, картинка попапа.
- **Сборки**: цены, описания, файлы для скачивания, скриншоты (любое количество).
- **Пользователи**: поиск, изменение баланса, удаление.
- **Отзывы**: поиск, модерация, удаление.
- **Ключи пополнения**: генерация ключей на сумму + кол-во активаций. Каждый юзер может активировать ключ один раз.
- **FAQ**: CRUD.

## 💳 Оплата

- **С баланса** — мгновенно, сборка доступна в профиле.
- **Крипта / FunPay / Discord** — перенаправляет на ссылку из админ-настроек.

## 📦 Структура

```
app.py              # вся серверная логика
templates/          # Jinja2 шаблоны
  base.html, index.html
  auth/login,register,verify.html
  admin/*.html
static/css/style.css
static/js/main.js, particles.js
static/uploads/     # загрузки (картинки, файлы сборок)
requirements.txt
Procfile
railway.json
.env.example
```

## 📝 Заметки

- OAuth через Discord/Google работает только если заданы `*_CLIENT_ID` и `*_CLIENT_SECRET`.
- Email-код приходит только если заполнены `MAIL_*` (используйте app-password Gmail).
- Для SQLite файл БД лежит в `instance/blackdev.db`. На Railway используйте Postgres (он сохраняется между рестартами).

Удачи! 🔥

## Реальная БД (PostgreSQL на Railway)
1. В Railway проекте: New → Database → **Add PostgreSQL**.
2. Railway автоматически добавит переменную `DATABASE_URL` в твой сервис.
3. Перезапусти деплой — приложение само переключится с SQLite на Postgres (URL `postgres://` нормализуется в `postgresql://` автоматически).
4. Таблицы создаются на старте (`db.create_all()`).
