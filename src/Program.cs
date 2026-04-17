using System;
using System.Threading;
using System.Windows.Forms;

namespace hSignerBridge;

static class Program
{
    [STAThread]
    static void Main()
    {
        using var mutex = new Mutex(true, "hSignerBridge_SingleInstance", out bool createdNew);
        if (!createdNew)
        {
            MessageBox.Show("hSignerBridge đã đang chạy.", "hSignerBridge",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}
