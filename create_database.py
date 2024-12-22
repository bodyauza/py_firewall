# Файл: create_database.py
import sqlite3
# Создаем соединение с базой данных
conn = sqlite3.connect('harmful_IP.db')
# Закрываем соединение
conn.close()