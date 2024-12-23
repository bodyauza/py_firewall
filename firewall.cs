using System;
using System.Data.SQLite;
using System.Diagnostics;
using System.Windows.Forms;
using SharpPcap;
using PacketDotNet;

namespace FirewallApp
{
    public partial class MainForm : Form
    {
        private CaptureDeviceList devices;
        private ICaptureDevice device;
        private SQLiteConnection conn;

        public MainForm()
        {
            InitializeComponent();
            this.Text = "Брандмауэр";
            this.label.Text = "Управление брандмауэром";
            this.startButton.Click += StartFirewall;
            this.stopButton.Click += StopFirewall;

            // Создаем соединение с базой данных
            conn = new SQLiteConnection("Data Source=harmful_IP.db;Version=3;");
            conn.Open();
        }

        private void StartFirewall(object sender, EventArgs e)
        {
            // Получаем список устройств
            devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                MessageBox.Show("Нет доступных устройств.");
                return;
            }

            // Выбираем первое устройство
            device = devices[0];
            device.OnPacketArrival += new PacketArrivalEventHandler(ProcessPacket);
            device.Open(DeviceMode.Promiscuous);
            device.StartCapture();

            statusLabel.Text = "Статус: Запущен";
        }

        private void StopFirewall(object sender, EventArgs e)
        {
            if (device != null && device.IsOpen)
            {
                device.StopCapture();
                device.Close();
            }

            statusLabel.Text = "Статус: Не запущен";
        }

        private void ProcessPacket(object sender, CaptureEventArgs e)
        {
            var packet = Packet.ParsePacket(e.Packet);
            var ipPacket = packet.Extract<IpPacket>();

            if (ipPacket != null)
            {
                string ip = ipPacket.SourceAddress.ToString();

                using (var command = new SQLiteCommand("SELECT * FROM BadIP WHERE ip = @ip", conn))
                {
                    command.Parameters.AddWithValue("@ip", ip);
                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.HasRows)
                        {
                            Console.WriteLine($"Блокировка пакета от {ip}");
                            // Здесь можно добавить логику для блокировки пакета
                        }
                        else
                        {
                            Console.WriteLine($"Разрешение пакета от {ip}");
                            // Здесь можно добавить логику для разрешения пакета
                        }
                    }
                }
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            StopFirewall(this, EventArgs.Empty);
            conn.Close();
            base.OnFormClosing(e);
        }
    }
}
