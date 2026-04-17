using System;
using System.Drawing;
using System.Windows.Forms;

namespace hSignerBridge;

/// <summary>
/// System tray app — ẩn window, hiện icon trong system tray.
/// </summary>
public class MainForm : Form
{
    private readonly NotifyIcon _trayIcon;
    private readonly ContextMenuStrip _trayMenu;
    private readonly BridgeWebSocketServer _wsServer;
    private readonly ToolStripMenuItem _statusItem;
    private readonly ToolStripMenuItem _clientsItem;

    private const int WsPort = 9505;

    public MainForm()
    {
        // Ẩn window hoàn toàn
        WindowState = FormWindowState.Minimized;
        ShowInTaskbar = false;
        Visible = false;
        Text = "hSignerBridge";
        Size = new Size(1, 1);
        Opacity = 0;

        // Build tray menu
        _trayMenu = new ContextMenuStrip();

        var titleItem = new ToolStripMenuItem("hSignerBridge v1.0")
        { Enabled = false, Font = new Font("Segoe UI", 9f, FontStyle.Bold) };
        _trayMenu.Items.Add(titleItem);
        _trayMenu.Items.Add(new ToolStripSeparator());

        _statusItem = new ToolStripMenuItem("Trạng thái: Đang khởi động...")
        { Enabled = false, Image = null };
        _trayMenu.Items.Add(_statusItem);

        _clientsItem = new ToolStripMenuItem("Kết nối: 0 client")
        { Enabled = false };
        _trayMenu.Items.Add(_clientsItem);

        _trayMenu.Items.Add(new ToolStripSeparator());

        var listCertsItem = new ToolStripMenuItem("Danh sách chứng thư số");
        listCertsItem.Click += OnListCerts;
        _trayMenu.Items.Add(listCertsItem);

        _trayMenu.Items.Add(new ToolStripSeparator());

        var exitItem = new ToolStripMenuItem("Thoát");
        exitItem.Click += OnExit;
        _trayMenu.Items.Add(exitItem);

        // Tray icon
        _trayIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "hSignerBridge - Cầu nối ký số",
            ContextMenuStrip = _trayMenu,
            Visible = true
        };
        _trayIcon.DoubleClick += OnListCerts;

        // Start WebSocket server
        _wsServer = new BridgeWebSocketServer(WsPort, this);
        _wsServer.OnLog += (msg) =>
        {
            try
            {
                if (InvokeRequired)
                    Invoke(() => UpdateStatus(msg));
                else
                    UpdateStatus(msg);
            }
            catch { }
        };
        _wsServer.Start();

        _statusItem.Text = $"Trạng thái: Đang chạy (port {WsPort})";
        _trayIcon.ShowBalloonTip(3000, "hSignerBridge",
            $"Cầu nối ký số đã sẵn sàng\nwss://localhost:{WsPort}", ToolTipIcon.Info);
    }

    private void UpdateStatus(string message)
    {
        _clientsItem.Text = $"Kết nối: {_wsServer.ConnectedClients} client";
        _trayIcon.Text = $"hSignerBridge - {_wsServer.ConnectedClients} client\n{message}";
    }

    private void OnListCerts(object? sender, EventArgs e)
    {
        try
        {
            var certs = CertificateHelper.ListSigningCertificates();
            if (certs.Count == 0)
            {
                MessageBox.Show("Không tìm thấy chứng thư số nào có private key.\n\n" +
                    "Vui lòng kiểm tra:\n" +
                    "- USB token đã cắm và driver đã cài\n" +
                    "- Certificate đã import vào Windows Certificate Store",
                    "hSignerBridge - Chứng thư số", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using var dlg = new Form
            {
                Text = $"hSignerBridge - Chứng thư số ({certs.Count})",
                Size = new Size(900, 500),
                StartPosition = FormStartPosition.CenterScreen,
                MinimizeBox = false,
                ShowInTaskbar = true,
                TopMost = true,
            };

            var lv = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                MultiSelect = false,
            };
            lv.Columns.Add("Loại", 90);
            lv.Columns.Add("Chủ sở hữu (Subject)", 340);
            lv.Columns.Add("Nhà phát hành", 200);
            lv.Columns.Add("Serial", 110);
            lv.Columns.Add("HSD", 90);
            lv.Columns.Add("Key", 60);

            foreach (var c in certs)
            {
                var cn = ExtractCn(c.Subject);
                var item = new ListViewItem(c.TokenType);
                item.SubItems.Add(cn);
                item.SubItems.Add(c.Issuer);
                item.SubItems.Add(c.Serial);
                item.SubItems.Add(c.NotAfter);
                item.SubItems.Add(c.KeyAlgorithm);
                item.ToolTipText = c.Subject;
                lv.Items.Add(item);
            }
            lv.ShowItemToolTips = true;

            dlg.Controls.Add(lv);
            dlg.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Lỗi liệt kê chứng thư số:\n{ex.Message}",
                "hSignerBridge", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static string ExtractCn(string subject)
    {
        var m = System.Text.RegularExpressions.Regex.Match(subject, @"CN=([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.Trim() : subject;
    }

    private void OnExit(object? sender, EventArgs e)
    {
        _wsServer.Stop();
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        Application.Exit();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            // Thu nhỏ xuống tray thay vì đóng
            e.Cancel = true;
            Hide();
            return;
        }
        _wsServer.Stop();
        _trayIcon.Visible = false;
        base.OnFormClosing(e);
    }

    protected override void SetVisibleCore(bool value)
    {
        // Không bao giờ hiện window
        base.SetVisibleCore(false);
    }
}
