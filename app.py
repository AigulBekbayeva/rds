from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_file, current_app, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import pandas as pd
from datetime import datetime
from models import User, Fire, AuditLog
from forms import FireForm, LoginForm, ExportForm
from flask_migrate import Migrate
from extensions import db
from functools import wraps
from regions import REGIONS_AND_LOCATIONS
from sqlalchemy.sql import func
import logging

from dash import Dash
from dashboard import create_dash_app  #
    

app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

with app.app_context():
    create_dash_app(app)

def roles_required(*roles):
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.roles not in roles:
                flash("Доступ запрещен.")
                return abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Успешный вход в систему.')
            if user.roles == 'engineer':
                return redirect(url_for('dashboard', region=user.region))
            elif user.roles == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.')
    return redirect(url_for('login'))


@app.route('/form', methods=['GET', 'POST'])
@roles_required('operator', 'admin', 'engineer')

def form_page():
    form = FireForm()

    if current_user.roles == 'admin':
        form.region.choices = [(region, region) for region in REGIONS_AND_LOCATIONS.keys()]
        selected_region = request.form.get('region', form.region.data)  # Выбранный регион
        form.location.choices = [(loc, loc) for loc in REGIONS_AND_LOCATIONS.get(selected_region, [])]
    elif current_user.roles in ['operator', 'engineer']:
        user_region = current_user.region
        form.region.choices = [(user_region, user_region)]
        form.location.choices = [(location, location) for location in REGIONS_AND_LOCATIONS.get(user_region, [])]

    if form.validate_on_submit():
        print("Данные формы:", form.data)

        file = request.files.get('file')
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        try:
            new_fire = Fire(
                date=form.date.data,
                region=form.region.data,
                location=form.location.data,
                branch=form.branch.data,
                forestry=form.forestry.data,
                quarter=form.quarter.data,
                allotment=form.allotment.data,
                damage_area=form.damage_area.data,
                damage_les=form.damage_les.data,
                damage_les_lesopokryt=form.damage_les_lesopokryt.data,
                damage_les_verh=form.damage_les_verh.data,
                damage_not_les=form.damage_not_les.data,
                LO_flag=form.LO_flag.data,
                LO_people_count=form.LO_people_count.data,
                LO_tecnic_count=form.LO_tecnic_count.data,
                APS_flag=form.APS_flag.data,
                APS_people_count=form.APS_people_count.data,
                APS_tecnic_count=form.APS_tecnic_count.data,
                APS_aircraft_count=form.APS_aircraft_count.data,
                KPS_flag=form.KPS_flag.data,
                KPS_people_count=form.KPS_people_count.data,
                KPS_tecnic_count=form.KPS_tecnic_count.data,
                KPS_aircraft_count=form.KPS_aircraft_count.data,
                MIO_flag=form.MIO_flag.data,
                MIO_people_count=form.MIO_people_count.data,
                MIO_tecnic_count=form.MIO_tecnic_count.data,
                MIO_aircraft_count=form.MIO_aircraft_count.data,
                other_org_flag=form.other_org_flag.data,
                other_org_people_count=form.other_org_people_count.data,
                other_org_tecnic_count=form.other_org_tecnic_count.data,
                other_org_aircraft_count=form.other_org_aircraft_count.data,
                description=form.description.data,
                damage_tenge=form.damage_tenge.data,
                firefighting_costs=form.firefighting_costs.data,
                KPO=form.KPO.data,
                file_path=filename
            )
            db.session.add(new_fire)
            db.session.commit()
            flash('Данные успешно добавлены!')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            print("Ошибка сохранения данных в базе:", e)
            flash("Ошибка при сохранении данных: " + str(e), "danger")
    else:
        print("Ошибки валидации формы:", form.errors)

    return render_template('form.html', form=form, regions_and_locations=REGIONS_AND_LOCATIONS)

def log_event(username, action, table_name, record_id, changes=None):
    log = AuditLog(
        timestamp=datetime.utcnow(),
        username=username,
        action=action,
        table_name=table_name,
        record_id=record_id,
        changes=changes
    )
    db.session.add(log)
    db.session.commit()


@app.route('/edit/<int:fire_id>', methods=['GET', 'POST'])
@roles_required('admin', 'engineer')
def edit_fire(fire_id):
    fire = Fire.query.get_or_404(fire_id)  
    form = FireForm(obj=fire)  

    if current_user.roles == 'admin':
        form.region.choices = [(region, region) for region in REGIONS_AND_LOCATIONS.keys()]
        form.location.choices = [(location, location) for location in REGIONS_AND_LOCATIONS.get(fire.region, [])]
    elif current_user.roles == 'engineer':
        form.region.choices = [(current_user.region, current_user.region)]
        form.location.choices = [(location, location) for location in REGIONS_AND_LOCATIONS.get(current_user.region, [])]

    if current_user.roles == 'engineer' and fire.region != current_user.region:
        flash('У вас нет прав редактировать этот пожар.', 'danger')
        return redirect(url_for('admin_dashboard'))

    old_data = {col.name: getattr(fire, col.name) for col in Fire.__table__.columns}

    if form.validate_on_submit():
        try:
            form.populate_obj(fire)

            file = request.files.get('file')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                fire.file_path = filename

            db.session.commit()

            changes = [
                f"{key}: {old_data[key]} -> {getattr(fire, key)}"
                for key in old_data
                if old_data[key] != getattr(fire, key)
            ]
            if changes:
                log_event(
                    username=current_user.username,
                    action="Обновление",
                    table_name="Fire",
                    record_id=fire.id,
                    changes="; ".join(changes)
                )

            flash('Данные успешно обновлены!', 'success')
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении данных: {e}', 'danger')
        print("Роль пользователя:", current_user.roles)
        print("Доступные регионы:", form.region.choices)
        print("Доступные территории:", form.location.choices)
        print("Данные формы:", form.data)
    return render_template('edit_fire.html', form=form, fire=fire)

@app.route('/delete/<int:fire_id>', methods=['POST'])
@roles_required('admin')
def delete_fire(fire_id):
    try:

        fire = Fire.query.get_or_404(fire_id)

        log_event(
            username=current_user.username,
            action="Удаление",
            table_name="Fire",
            record_id=fire.id,
            changes=f"Удалена запись о пожаре с ID {fire.id}"
        )

        db.session.delete(fire)
        db.session.commit()
        flash(f"Запись о пожаре с ID {fire_id} успешно удалена.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Ошибка при удалении записи: {e}", "danger")

    return redirect(url_for('admin_dashboard'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route('/admin-dashboard')
@roles_required('admin', 'engineer', 'analyst')
def admin_dashboard():
    fires = Fire.query.order_by(Fire.date.desc()).all() if current_user.roles != 'engineer' else Fire.query.filter_by(region=current_user.region).order_by(Fire.date.desc()).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all() if current_user.roles == 'admin' else []
    return render_template('admin_dashboard.html', fires=fires, audit_logs=audit_logs, current_role=current_user.roles)


@app.route('/download/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    # Установка логирования
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("download_logs")

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Проверка наличия файла
        if not os.path.exists(file_path):
            logger.error(f"Файл не найден: {file_path}")
            flash("Файл не найден", "danger")
            return redirect(url_for("dashboard"))

        # Отправка файла клиенту
        logger.info(f"Отправка файла: {file_path}")
        return send_file(file_path, as_attachment=True)

    except Exception as e:
        # Логирование ошибок
        logger.error(f"Ошибка скачивания файла: {str(e)}", exc_info=True)
        flash("Произошла ошибка при скачивании файла", "danger")
        return redirect(url_for("dashboard"))




@app.route('/dashboard')
def dashboard():
    # Просто перенаправляем на страницу с встроенным Dash
    return render_template('dashboard.html')
    
@app.route('/export', methods=['GET', 'POST'])
@roles_required('admin', 'analyst')
def export():
    form = ExportForm()

    # Установка логирования
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("export_logs")

    try:
        if form.validate_on_submit():
            start_date = form.start_date.data
            end_date = form.end_date.data
            query = Fire.query

            # Фильтрация по дате
            if start_date:
                query = query.filter(Fire.date >= start_date)
                logger.info(f"Фильтрация по начальной дате: {start_date}")
            if end_date:
                query = query.filter(Fire.date <= end_date)
                logger.info(f"Фильтрация по конечной дате: {end_date}")

            # Получение данных из базы
            fires = query.all()
            logger.info(f"Найдено записей: {len(fires)}")

            # Формирование данных для экспорта
            fire_data = [
                {
                    "ID пожара": fire.id,
                    "Дата пожара": fire.date,
                    "Область": fire.region,
                    "КГУ/ООПТ": fire.location,
                    "Филиал": fire.branch,
                    "Лесничество": fire.forestry,
                    "Квартал": fire.quarter,
                    "Выдел": fire.allotment,
                    "Площадь пожара": fire.damage_area,
                    "Лесная площадь": fire.damage_les,
                    "Лесопокрытая площадь": fire.damage_les_lesopokryt,
                    "Верховой пожар": fire.damage_les_verh,
                    "Нелесная площадь": fire.damage_not_les,
                    "Лесная охрана": "Да" if fire.LO_flag else "Нет",
                    "Кол-во людей Лесной охраны": fire.LO_people_count,
                    "Кол-во техники Лесной охраны": fire.LO_tecnic_count,
                    "АПС": "Да" if fire.APS_flag else "Нет",
                    "Кол-во людей АПС": fire.APS_people_count,
                    "Кол-во техники АПС": fire.APS_tecnic_count,
                    "Кол-во возд.судов АПС": fire.APS_aircraft_count,
                    "КПС": "Да" if fire.KPS_flag else "Нет",
                    "Кол-во людей КПС": fire.KPS_people_count,
                    "Кол-во техники КПС": fire.KPS_tecnic_count,
                    "Кол-во возд.судов КПС": fire.KPS_aircraft_count,
                    "МИО": "Да" if fire.MIO_flag else "Нет",
                    "Кол-во людей МИО": fire.MIO_people_count,
                    "Кол-во техники МИО": fire.MIO_tecnic_count,
                    "Кол-во возд.судов МИО": fire.MIO_aircraft_count,
                    "др. организации": "Да" if fire.other_org_flag else "Нет",
                    "Кол-во людей др.орг": fire.other_org_people_count,
                    "Кол-во техники др.орг": fire.other_org_tecnic_count,
                    "Кол-во возд.судов др.орг": fire.other_org_aircraft_count,
                    "Описание": fire.description,
                    "Ущерб (тенге)": fire.damage_tenge,
                    "Затраты на тушение": fire.firefighting_costs,
                    "КПО": fire.KPO,
                }
                for fire in fires
            ]

            # Сохранение в файл
            csv_file = os.path.join("/tmp", "fire_data_export.csv")
            logger.info(f"Сохранение данных в файл: {csv_file}")
            df = pd.DataFrame(fire_data)
            df.to_csv(csv_file, index=False, encoding='utf-8-sig')

            # Отправка файла пользователю
            logger.info(f"Отправка файла: {csv_file}")
            return send_file(csv_file, as_attachment=True, mimetype='text/csv')

    except Exception as e:
        # Логирование ошибок
        logger.error(f"Ошибка экспорта: {str(e)}", exc_info=True)
        flash("Произошла ошибка при экспорте данных", "danger")
        return redirect(url_for("admin_dashboard"))

    return render_template('export.html', form=form)

def translate_changes(changes):
    if not changes:
        return "Нет изменений"

    translated_changes = []
    change_list = changes.split("; ")
    for change in change_list:
        if ": " in change:
            column, values = change.split(": ", 1)
            column_translations = {
                "branch": "Филиал",
                "forestry": "Лесничество",
                "quarter": "Квартал",
                "allotment": "Выдел",
                "damage_area": "Площадь пожара",
                "damage_les": "Лесная площадь",
                "damage_les_lesopokryt": "Лесопокрытая площадь",
                "damage_les_verh": "Верховая площадь",
                "damage_not_les": "Нелесная площадь",
                "LO_flag": "Лесная охрана задействована",
                "LO_people_count": "Кол-во людей Лесной охраны",
                "LO_tecnic_count": "Кол-во техники Лесной охраны",
                "APS_flag": "АПС задействован",
                "APS_people_count": "Кол-во людей АПС",
                "APS_tecnic_count": "Кол-во техники АПС",
                "APS_aircraft_count": "Кол-во воздушных судов АПС",
                "KPS_flag": "КПС задействован",
                "KPS_people_count": "Кол-во людей КПС",
                "KPS_tecnic_count": "Кол-во техники КПС",
                "KPS_aircraft_count": "Кол-во воздушных судов КПС",
                "MIO_flag": "МИО задействован",
                "MIO_people_count": "Кол-во людей МИО",
                "MIO_tecnic_count": "Кол-во техники МИО",
                "MIO_aircraft_count": "Кол-во воздушных судов МИО",
                "other_org_flag": "Другие организации задействованы",
                "other_org_people_count": "Кол-во людей других организаций",
                "other_org_tecnic_count": "Кол-во техники других организаций",
                "other_org_aircraft_count": "Кол-во воздушных судов других организаций",
                "description": "Описание",
                "damage_tenge": "Ущерб (тенге)",
                "firefighting_costs": "Затраты на тушение (тенге)",
                "KPO": "КПО",
                "file_path": "Загрузить файл",
            }
            translated_column = column_translations.get(column, column)
            translated_changes.append(f"{translated_column}: {values}")
        else:
            translated_changes.append(f"Некорректные данные: {change}")

    return "; ".join(translated_changes)
@app.context_processor
def utility_processor():
    def translate_value(value):
        if value is None:
            return ""  
        if value is True:
            return "Да"
        if value is False:
            return "Нет"
        return value  
    return dict(translate_value=translate_value, translate_changes=translate_changes)
    
@app.route('/export-audit', methods=['GET'])
@roles_required('admin')
def export_audit():
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()

    audit_data = [
        {
            "Время": log.timestamp,
            "Пользователь": log.username,
            "Действие": log.action.replace("Update", "Обновление").replace("Delete", "Удаление").replace("Create", "Создание"),
            "Таблица": log.table_name,
            "ID записи": log.record_id,
            "Изменения": translate_changes(log.changes)
        }
        for log in audit_logs
    ]

    csv_file = os.path.join("/tmp", "audit_log_export.csv")
    df = pd.DataFrame(audit_data)
    df.to_csv(csv_file, index=False, encoding='utf-8-sig')
    return send_file(csv_file, as_attachment=True, mimetype='text/csv')


@app.route('/summary', methods=['GET', 'POST'])
@roles_required('admin', 'analyst')
def summary():
    from sqlalchemy.sql import func
    start_date = request.args.get('start_date', None)
    end_date = request.args.get('end_date', None)

    query = db.session.query(
        Fire.region,
        func.count(Fire.id).label('fire_count'),
        func.sum(func.coalesce(Fire.damage_area, 0)).label('total_damage_area'),
        func.sum(func.coalesce(Fire.damage_tenge, 0)).label('total_damage_tenge'),
        func.sum(
            func.coalesce(Fire.LO_people_count, 0) +
            func.coalesce(Fire.APS_people_count, 0) +
            func.coalesce(Fire.KPS_people_count, 0) +
            func.coalesce(Fire.MIO_people_count, 0) +
            func.coalesce(Fire.other_org_people_count, 0)
        ).label('total_people'),
        func.sum(
            func.coalesce(Fire.LO_tecnic_count, 0) +
            func.coalesce(Fire.APS_tecnic_count, 0) +
            func.coalesce(Fire.KPS_tecnic_count, 0) +
            func.coalesce(Fire.MIO_tecnic_count, 0) +
            func.coalesce(Fire.other_org_tecnic_count, 0)
        ).label('total_technics'),
        func.sum(
            func.coalesce(Fire.APS_aircraft_count, 0) +
            func.coalesce(Fire.KPS_aircraft_count, 0) +
            func.coalesce(Fire.MIO_aircraft_count, 0) +
            func.coalesce(Fire.other_org_aircraft_count, 0)
        ).label('total_aircraft'),
        func.sum(func.coalesce(Fire.APS_people_count, 0)).label('total_APS_people'),
        func.sum(func.coalesce(Fire.APS_tecnic_count, 0)).label('total_APS_technics'),
        func.sum(func.coalesce(Fire.APS_aircraft_count, 0)).label('total_APS_aircraft'),
    )

    if start_date:
        query = query.filter(Fire.date >= start_date)
    if end_date:
        query = query.filter(Fire.date <= end_date)

    summary_data = query.group_by(Fire.region).all()

    total_fire_count = sum(row.fire_count for row in summary_data)
    total_damage_area = sum(row.total_damage_area or 0 for row in summary_data)
    total_damage_tenge = sum(row.total_damage_tenge or 0 for row in summary_data)
    total_people = sum(row.total_people or 0 for row in summary_data)
    total_technics = sum(row.total_technics or 0 for row in summary_data)
    total_aircraft = sum(row.total_aircraft or 0 for row in summary_data)
    total_APS_people = sum(row.total_APS_people or 0 for row in summary_data)
    total_APS_technics = sum(row.total_APS_technics or 0 for row in summary_data)
    total_APS_aircraft = sum(row.total_APS_aircraft or 0 for row in summary_data)

    return render_template(
        'summary.html',
        summary_data=summary_data,
        start_date=start_date,
        end_date=end_date,
        totals={
            "fire_count": total_fire_count,
            "damage_area": total_damage_area,
            "damage_tenge": total_damage_tenge,
            "people": total_people,
            "technics": total_technics,
            "aircraft": total_aircraft,
            "APS_people": total_APS_people,
            "APS_technics": total_APS_technics,
            "APS_aircraft": total_APS_aircraft,
        }
    )



if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
    #app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
