import os
import subprocess
import tkinter as tk
from tkinter import messagebox
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import sqlite3

# Подключение к базе данных SQLite
conn = sqlite3.connect('harmful_IP.db')

class FirewallApp:
    def __init__(self, master):
        self.master = master
        master.title("Брандмауэр")

        self.label = tk.Label(master, text="Управление брандмауэром")
        self.label.pack()

        self.start_button = tk.Button(master, text="Запустить брандмауэр", command=self.start_firewall)
        self.start_button.pack()

        self.stop_button = tk.Button(master, text="Остановить брандмауэр", command=self.stop_firewall)
        self.stop_button.pack()

        self.status_label = tk.Label(master, text="Статус: Не запущен")
        self.status_label.pack()

        self.queue = NetfilterQueue()

    def start_firewall(self):
        # Настройка iptables
        os.system("iptables -A INPUT -j NFQUEUE --queue-num 1")

        # Запуск nfqueue в отдельном потоке
        self.queue.bind(1, self.process_packet)
        self.queue.run()

        self.status_label.config(text="Статус: Запущен")

    def stop_firewall(self):
        # Очистка iptables
        os.system("iptables -D INPUT -j NFQUEUE --queue-num 1")

        # Остановка nfqueue
        self.queue.unbind()

        self.status_label.config(text="Статус: Не запущен")

    def process_packet(self, packet):
        # Преобразование пакета в формат Scapy
        scapy_packet = scapy.IP(packet.get_payload())
        cursor = conn.cursor()
        ip = scapy_packet.src
        parameters = {'ip': ip}

        # Параметр внутри запроса определяется как :PARAM
        cursor.execute('SELECT * FROM BadIP WHERE ip = :ip', parameters)
        result = cursor.fetchall()

        # Логика обработки пакетов
        if len(result) > 0:
            print(f"Блокировка пакета от {scapy_packet.src}")
            packet.drop()  # Блокируем пакет
        else:
            print(f"Разрешение пакета от {scapy_packet.src}")
            packet.accept()  # Разрешаем пакет

    def on_closing(self):
        self.stop_firewall()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

# Версия с режимом "Предупреждение передачи данных пользователя". 
"""
import os
import subprocess
import tkinter as tk
from tkinter import messagebox
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import sqlite3

class FirewallApp:
    def __init__(self, master):
        self.master = master
        master.title("Брандмауэр")

        self.mode = "block"  # Режим по умолчанию

        self.label = tk.Label(master, text="Управление брандмауэром")
        self.label.pack()

        self.start_button = tk.Button(master, text="Запустить брандмауэр", command=self.start_firewall)
        self.start_button.pack()

        self.stop_button = tk.Button(master, text="Остановить брандмауэр", command=self.stop_firewall)
        self.stop_button.pack()

        self.warning_mode_button = tk.Button(master, text="Включить режим предупреждения", command=self.toggle_warning_mode)
        self.warning_mode_button.pack()

        self.status_label = tk.Label(master, text="Статус: Не запущен")
        self.status_label.pack()

        self.queue = NetfilterQueue()
        self.conn = sqlite3.connect('harmful_IP.db')  # Соединение с БД

    def toggle_warning_mode(self):
        if self.mode == "block":
            self.mode = "warn"
            self.warning_mode_button.config(text="Выключить режим предупреждения")
            messagebox.showinfo("Режим предупреждения", "Режим предупреждения включен.")
        else:
            self.mode = "block"
            self.warning_mode_button.config(text="Включить режим предупреждения")
            messagebox.showinfo("Режим предупреждения", "Режим предупреждения выключен.")

    def start_firewall(self):
        os.system("iptables -A INPUT -j NFQUEUE --queue-num 1")
        
        # Запуск nfqueue в отдельном потоке
        self.queue.bind(0, self.process_packet)
        self.queue.run()

        self.status_label.config(text="Статус: Запущен")

    def stop_firewall(self):
        os.system("iptables -D INPUT -j NFQUEUE --queue-num 1")
        
        # Остановка nfqueue
        self.queue.unbind()

        self.status_label.config(text="Статус: Не запущен")

    def process_packet(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        cursor = self.conn.cursor()
        ip = scapy_packet.src
        
        # Проверка на наличие IP в таблице BadIP
        cursor.execute('SELECT * FROM BadIP WHERE ip = ?', (ip,))
        result = cursor.fetchall()

        if result:  # Если IP найден в таблице
            print(f"Блокировка пакета от {scapy_packet.src}")
            packet.drop()  # Блокируем пакет
        elif self.mode == "warn":  # Если включен режим предупреждения
            user_response = messagebox.askyesno("Предупреждение", f"Попытка передачи данных от {scapy_packet.src}. Подтвердить передачу?")
            if user_response:
                print(f"Разрешение пакета от {scapy_packet.src}")
                packet.accept()  # Разрешаем пакет
            else:
                print(f"Блокировка пакета от {scapy_packet.src}")
                packet.drop()  # Блокируем пакет
        else:  # В обычном режиме
            print(f"Разрешение пакета от {scapy_packet.src}")
            packet.accept()  # Разрешаем пакет

    def on_closing(self):
        self.stop_firewall()
        self.conn.close()  # Закрытие соединения с БД
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
"""
