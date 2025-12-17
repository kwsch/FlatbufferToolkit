using System;
using System.Windows.Forms;

public sealed class Logger
{
    private static Logger _instance;
    private static readonly object _lock = new();

    private readonly TextBox _textBox;

    private Logger(TextBox textBox)
    {
        _textBox = textBox ?? throw new ArgumentNullException(nameof(textBox));
    }

    public static void Initialize(ref TextBox textBox)
    {
        lock (_lock)
        {
            if (_instance != null)
                throw new InvalidOperationException("Logger already initialized");

            _instance = new Logger(textBox);
        }
    }

    public static Logger Instance
    {
        get
        {
            if (_instance == null)
                throw new InvalidOperationException("Logger not initialized");

            return _instance;
        }
    }

    public void Log(string message)
    {
        if (_textBox.IsDisposed)
            return;

        string line = $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";

        if (_textBox.InvokeRequired)
        {
            _textBox.BeginInvoke(new Action(() =>
            {
                _textBox.AppendText(line);
            }));
        }
        else
        {
            _textBox.AppendText(line);
        }
    }
}
