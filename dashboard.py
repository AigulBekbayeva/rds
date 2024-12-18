from dash import Dash, dcc, html, Input, Output, ctx, State
import pandas as pd
import plotly.express as px
import os
import json
from extensions import db
from models import Fire
from plotly import graph_objects as go
from functools import lru_cache
# Функция для получения данных
def fetch_fire_data():
    """Fetch fire data from the database."""
    fire_data = db.session.query(Fire.date, Fire.region, Fire.damage_area, Fire.damage_tenge).all()
    return pd.DataFrame([
        {"region": fire.region,
         "year": fire.date.year if fire.date else None,
         "month": fire.date.month if fire.date else None,
         "damage_area": fire.damage_area or 0,
         "damage_tenge": fire.damage_tenge or 0}
        for fire in fire_data
    ])

# Функция создания Dash-приложения
def create_dash_app(flask_app):
    dash_app = Dash(server=flask_app, name="Dashboard", url_base_pathname="/dash/")

    # Получение данных
    data = fetch_fire_data()
    
    # --- Кэширование GeoJSON-файла ---
    geojson_cache = None  # Глобальная переменная для кэширования GeoJSON
    if not geojson_cache:
        geojson_path = os.path.join('static', 'geojson', 'regions.geojson')
        with open(geojson_path, 'r', encoding='utf-8') as geojson_file:
            geojson_cache = json.load(geojson_file)
         
    
    # --- Функция с кэшированием данных ---
    @lru_cache(maxsize=32)  # Кэшируем до 32 комбинаций входных значений
    def get_cached_data(selected_year):
        filtered = data.copy()
        if selected_year != 'all':
            filtered = filtered[filtered['year'] == selected_year]
        return filtered
        
    # Макет Dash
    dash_app.layout = html.Div([
        html.H1("Аналитика лесных пожаров", style={'textAlign': 'center'}),

        # Выпадающий фильтр по годам
        html.Div([
            html.Label("Выберите год:"),
            dcc.Dropdown(
                id='year-dropdown',
                options=[{'label': 'Все года', 'value': 'all'}] +
                        [{'label': year, 'value': year} for year in sorted(data['year'].dropna().unique())],
                value='all',
                placeholder="Выберите год",
                style={'width': '50%'}
            ),
            html.Button("Сбросить фильтр", id='reset-button', n_clicks=0, style={'margin-left': '20px'})
        ], style={'display': 'flex', 'justify-content': 'center', 'margin-bottom': '20px'}),

        # Индикаторы с ленивой загрузкой
        html.Div([
            html.Div([
                dcc.Loading(
                    type="circle",
                    children=dcc.Graph(id='fire-count-indicator', style={
                        'width': '250px', 'height': '120px',
                        'background-color': '#4CAF50',
                        'border-radius': '10px'
                    })
                )
            ], style={'margin': '0 auto'}),

            html.Div([
                dcc.Loading(
                    type="circle",
                    children=dcc.Graph(id='fire-area-indicator', style={
                        'width': '250px', 'height': '120px',
                        'background-color': '#4CAF50',
                        'border-radius': '10px'
                    })
                )
            ], style={'margin': '0 auto'})
        ], style={'display': 'flex', 'justify-content': 'center', 'gap': '20px', 'margin-bottom': '10px'}),

        # Две колонки с ленивыми графиками
        html.Div([
            # Левая колонка: карта и количество по регионам
            html.Div([
                dcc.Loading(
                    type="circle",
                    children=dcc.Graph(id='fire-map')
                ),
                dcc.Loading(
                    type="circle",
                    children=dcc.Graph(id='fire-chart')
                )
            ], style={'width': '48%', 'display': 'inline-block', 'padding': '0 10px'}),

            # Правая колонка: по месяцам и ущерб
            html.Div([
                dcc.Loading(
                    type="circle",
                    children=dcc.Graph(id='fire-month-chart')
                ),
                dcc.Loading(
                    type="circle",
                    children=dcc.Graph(id='damage-chart')
                )
            ], style={'width': '48%', 'display': 'inline-block', 'padding': '0 10px'})
        ], style={'display': 'flex', 'justify-content': 'space-between'})
    ])


    # Callback для обновления графиков
    @dash_app.callback(
        [Output('fire-map', 'figure'),
         Output('fire-chart', 'figure'),
         Output('fire-month-chart', 'figure'),
         Output('damage-chart', 'figure'),
         Output('fire-count-indicator', 'figure'),
         Output('fire-area-indicator', 'figure')],
        [Input('year-dropdown', 'value'),
         Input('fire-map', 'clickData'),
         Input('reset-button', 'n_clicks')]
        
    )
    def update_graphs(selected_year, click_data, reset_clicks):
        data = fetch_fire_data()
        filtered_data = get_cached_data(selected_year)
    # Если нажата кнопка сброса
        if 'reset-button' == ctx.triggered_id:
            selected_year = 'all'
            click_data = None

        # Фильтрация данных
        filtered_data = data.copy()
        if selected_year != 'all':
            filtered_data = filtered_data[filtered_data['year'] == selected_year]
        if click_data and 'points' in click_data:
            selected_region = click_data['points'][0]['location']
            filtered_data = filtered_data[filtered_data['region'] == selected_region]
            
            
        # Расчёт индикаторов
        total_fires = len(filtered_data)
        total_area = filtered_data['damage_area'].sum()

        # Индикатор "Количество пожаров"
        fire_count_indicator = go.Figure(go.Indicator(
            mode="number",
            value=total_fires,
            title={"text": "<b>Количество<br>пожаров</b>", "font": {"size": 18}},
            number={'font': {'size': 40, 'color': 'white'}},
            domain={'x': [0, 1], 'y': [0, 1]}
        ))
        fire_count_indicator.update_layout(
            paper_bgcolor='#4CAF50',  # Фон индикатора
            height=120,  # Высота индикатора
            margin=dict(l=10, r=10, t=30, b=10),
            title_x=0.5  
            
        )

        # Индикатор "Площадь пожаров"
        fire_area_indicator = go.Figure(go.Indicator(
            mode="number",
            value=total_area,
            title={"text": "<b>Площадь<br>пожаров (га)</b>", "font": {"size": 18}},
            number={'font': {'size': 40, 'color': 'white'}},
            domain={'x': [0, 1], 'y': [0, 1]} 
        ))
        fire_area_indicator.update_layout(
            paper_bgcolor='#4CAF50',  # Фон индикатора
            height=120,  # Высота индикатора
            margin=dict(l=10, r=10, t=30, b=10),
            title_x=0.5 
             
        )

        def categorize_damage(value):
            """Функция для категоризации ущерба."""
            if pd.isna(value) or value == 0:
                return '0'
            elif value <= 10:
                return '0-10'
            elif value <= 100:
                return '10-100'
            elif value <= 1000:
                return '100-1000'
            else:
                return 'более 1000'
        # Агрегирование данных по регионам
        aggregated_data = filtered_data.groupby('region', as_index=False).agg({'damage_area': 'sum'})

        # Создаем колонку с категориями ущерба
        aggregated_data['damage_category'] = aggregated_data['damage_area'].apply(categorize_damage)

        # Объединяем все регионы из GeoJSON с нашими данными
        all_regions = pd.DataFrame({'region': [feature['properties']['region'] for feature in geojson_cache['features']]})
        map_data = all_regions.merge(aggregated_data, on='region', how='left')

        # Заполняем пустые значения как 'Нет данных'
        map_data['damage_category'] = map_data['damage_category'].fillna('0')

        # Настраиваем цвета для категорий
        color_scale = {
            '0': 'gray',
            '0-10': '#ffffb2',
            '10-100': '#fd8d3c',
            '100-1000': '#f03b20',
            'более 1000': '#bd0026'
        }

        # Построение карты
        map_fig = px.choropleth_mapbox(
            map_data,
            geojson=geojson_cache,
            locations="region",
            featureidkey="properties.region",
            color="damage_category",
            color_discrete_map=color_scale,
            title="Площадь пожаров по областям",
            center={"lat": 48.0, "lon": 68.0},
            zoom=3,
            hover_data=["damage_area"],
            labels={"damage_category": "Площадь пожаров"} 
        )
        map_fig.update_layout(
            mapbox_style="carto-positron",
            coloraxis_showscale=False  # Убираем непрерывную шкалу
        )
        # Добавляем колонку с названиями месяцев
        month_names = {
            1: 'Январь', 2: 'Февраль', 3: 'Март', 4: 'Апрель', 5: 'Май',
            6: 'Июнь', 7: 'Июль', 8: 'Август', 9: 'Сентябрь', 10: 'Октябрь',
            11: 'Ноябрь', 12: 'Декабрь'
        }
        filtered_data['month_name'] = filtered_data['month'].map(month_names)

        # --- График по регионам ---
        region_data = filtered_data.groupby(['region', 'year'], as_index=False).size().pivot(
            index='region', columns='year', values='size').fillna(0)
        fire_chart = go.Figure()
        for year in region_data.columns:
            fire_chart.add_trace(go.Bar(
                x=region_data.index,
                y=region_data[year],
                name=str(year)
            ))
        fire_chart.update_layout(
            title="Количество пожаров по областям",
            xaxis_title="Регион",
            yaxis_title="Количество пожаров",
            barmode='group'
        )

        # --- График по месяцам ---
        month_data = filtered_data.groupby(['month_name', 'year'], as_index=False).size().pivot(
            index='month_name', columns='year', values='size').fillna(0)
        fire_month_chart = go.Figure()
        for year in month_data.columns:
            fire_month_chart.add_trace(go.Bar(
                x=month_data.index,
                y=month_data[year],
                name=str(year)
            ))
        fire_month_chart.update_layout(
            title="Количество пожаров по месяцам",
            xaxis_title="Месяц",
            yaxis_title="Количество пожаров",
            barmode='group'
        )

        # --- График ущерба по регионам ---
        damage_data = filtered_data.groupby(['region', 'year'], as_index=False).agg({'damage_tenge': 'sum'}).pivot(
            index='region', columns='year', values='damage_tenge').fillna(0)
        damage_chart = go.Figure()
        for year in damage_data.columns:
            damage_chart.add_trace(go.Bar(
                x=damage_data.index,
                y=damage_data[year],
                name=str(year)
            ))
        damage_chart.update_layout(
            title="Ущерб от пожаров по областям",
            xaxis_title="Регион",
            yaxis_title="Ущерб (тенге)",
            barmode='group'
        )

        return map_fig, fire_chart, fire_month_chart, damage_chart, fire_count_indicator, fire_area_indicator


    return dash_app
