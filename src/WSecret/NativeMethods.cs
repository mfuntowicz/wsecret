using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace WSecret;

/// <summary>
/// Raw Win32 interop plus the two native hosts the shell needs: a message-only
/// window (global hotkey + tray messages) and a tray icon. No secret material
/// is ever created, held, or logged in this file; the broker process owns all
/// secrets and the secure clipboard.
/// </summary>
internal static class Native
{
    // ---- handle / process constants -------------------------------------
    internal const int HANDLE_FLAG_INHERIT = 0x00000001;
    internal const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    internal const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    internal const uint CREATE_NO_WINDOW = 0x08000000;
    internal const int STARTF_USESTDHANDLES = 0x00000100;
    internal const int PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
    internal const uint WAIT_OBJECT_0 = 0;
    internal const uint WAIT_TIMEOUT = 0x102;
    internal const uint INFINITE = 0xFFFFFFFF;

    // ---- window / hotkey / tray constants -------------------------------
    internal const int HWND_MESSAGE = -3;
    internal const uint WM_HOTKEY = 0x0312;
    internal const uint WM_APP = 0x8000;
    internal const uint WM_TRAYICON = 0x8001;
    internal const uint WM_LBUTTONUP = 0x0202;
    internal const uint WM_LBUTTONDBLCLK = 0x0203;
    internal const uint WM_RBUTTONUP = 0x0205;
    internal const uint MOD_ALT = 0x0001;
    internal const uint MOD_CONTROL = 0x0002;
    internal const uint MOD_SHIFT = 0x0004;
    internal const uint MOD_WIN = 0x0008;
    internal const uint MOD_NOREPEAT = 0x4000;
    internal const uint NIM_ADD = 0x00000000;
    internal const uint NIM_MODIFY = 0x00000001;
    internal const uint NIM_DELETE = 0x00000002;
    internal const uint NIF_MESSAGE = 0x00000001;
    internal const uint NIF_ICON = 0x00000002;
    internal const uint NIF_TIP = 0x00000004;
    internal const uint MF_STRING = 0x00000000;
    internal const uint MF_SEPARATOR = 0x00000800;
    internal const uint MF_CHECKED = 0x00000008;
    internal const uint MF_GRAYED = 0x00000001;
    internal const uint TPM_RIGHTBUTTON = 0x0002;
    internal const uint TPM_RETURNCMD = 0x0100;
    internal const uint TPM_NONOTIFY = 0x0080;
    internal const int SW_RESTORE = 9;
    internal const uint IMAGE_ICON = 1;
    internal const int WM_DPICHANGED = 0x02E0;

    // ---- structs --------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFOW
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFOEXW
    {
        public STARTUPINFOW StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WNDCLASSEXW
    {
        public int cbSize;
        public int style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string? lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct POINT
    {
        public int x;
        public int y;
    }


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct NOTIFYICONDATAW
    {
        public int cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string? szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string? szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string? szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    internal delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    // ---- kernel32 -------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool CreateProcessW(
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFOEXW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GetExitCodeProcess(IntPtr hProcess, out int lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool TerminateProcess(IntPtr hProcess, int uExitCode);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    internal static extern IntPtr GetModuleHandleW(string? lpModuleName);

    // ---- user32 ---------------------------------------------------------

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr CreateWindowExW(int dwExStyle, string lpClassName, string lpWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll")]
    internal static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    [DllImport("user32.dll")]
    internal static extern uint GetDpiForWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    internal static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    internal static extern IntPtr SetActiveWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    internal static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, IntPtr uIDNewItem, string lpNewItem);

    [DllImport("user32.dll")]
    internal static extern uint TrackPopupMenu(IntPtr hMenu, uint uFlags, int x, int y, int nReserved, IntPtr hWnd, IntPtr prcRect);

    [DllImport("user32.dll")]
    internal static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr LoadImageW(IntPtr hInst, string lpszName, uint uType, int cxDesired, int cyDesired, uint fuLoad);

    // ---- shell32 --------------------------------------------------------

    [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);

    // ---- restricted broker launch ---------------------------------------

    /// <summary>
    /// Spawns the broker with inheritance restricted to exactly the listed
    /// handles (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), mirroring the Rust side's
    /// birth hardening. Standard handles are explicitly NULL (STARTF_USESTDHANDLES)
    /// and CREATE_NO_WINDOW suppresses the console-subsystem broker's console;
    /// masked input uses the separate native Win32 prompt process. Returns the
    /// raw process handle (caller closes) and the process id.
    /// </summary>
    internal static void LaunchBrokerWithInheritedHandles(
        string exePath,
        IReadOnlyList<string> arguments,
        IReadOnlyList<IntPtr> inheritableHandles,
        out IntPtr hProcess,
        out int processId)
    {
        if (inheritableHandles.Count == 0)
        {
            throw new ArgumentException("At least one inheritable handle is required.", nameof(inheritableHandles));
        }

        IntPtr attributeList = IntPtr.Zero;
        IntPtr handlesBuffer = IntPtr.Zero;
        try
        {
            IntPtr listSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref listSize);
            attributeList = Marshal.AllocHGlobal(listSize);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref listSize))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "InitializeProcThreadAttributeList failed.");
            }

            handlesBuffer = Marshal.AllocHGlobal(IntPtr.Size * inheritableHandles.Count);
            for (int i = 0; i < inheritableHandles.Count; i++)
            {
                Marshal.WriteIntPtr(handlesBuffer, i * IntPtr.Size, inheritableHandles[i]);
            }

            if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handlesBuffer,
                    (IntPtr)(IntPtr.Size * inheritableHandles.Count),
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "UpdateProcThreadAttribute failed.");
            }

            var siEx = new STARTUPINFOEXW
            {
                StartupInfo = new STARTUPINFOW
                {
                    // cb covers the extended structure; STARTF_USESTDHANDLES
                    // with NULL std handles keeps console handles out of the
                    // broker. Secret input never uses a console.
                    cb = Marshal.SizeOf<STARTUPINFOEXW>(),
                    dwFlags = STARTF_USESTDHANDLES,
                    hStdInput = IntPtr.Zero,
                    hStdOutput = IntPtr.Zero,
                    hStdError = IntPtr.Zero,
                },
                lpAttributeList = attributeList,
            };

            var commandLine = new StringBuilder();
            commandLine.Append('"').Append(exePath).Append('"');
            foreach (string argument in arguments)
            {
                commandLine.Append(' ').Append('"').Append(argument.Replace("\"", "\\\"")).Append('"');
            }

            if (!CreateProcessW(
                    exePath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true, // the two pipe ends must be inheritable
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    IntPtr.Zero,
                    null,
                    ref siEx,
                    out PROCESS_INFORMATION pi))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "CreateProcessW failed for wsecret-broker.exe.");
            }

            hProcess = pi.hProcess;
            processId = pi.dwProcessId;
            if (pi.hThread != IntPtr.Zero)
            {
                CloseHandle(pi.hThread);
            }
        }
        finally
        {
            if (attributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }

            if (handlesBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(handlesBuffer);
            }
        }
    }
}

/// <summary>A configurable global hotkey (modifiers + virtual key).</summary>
internal readonly record struct HotkeyChoice(bool Control, bool Alt, bool Shift, bool Win, uint VirtualKey)
{
    internal const uint ModAlt = Native.MOD_ALT;
    internal const uint ModControl = Native.MOD_CONTROL;
    internal const uint ModShift = Native.MOD_SHIFT;
    internal const uint ModWin = Native.MOD_WIN;

    internal uint Modifiers =>
        (Control ? ModControl : 0u) |
        (Alt ? ModAlt : 0u) |
        (Shift ? ModShift : 0u) |
        (Win ? ModWin : 0u) |
        Native.MOD_NOREPEAT;

    internal string DisplayText
    {
        get
        {
            var parts = new List<string>(5);
            if (Control) parts.Add("Ctrl");
            if (Alt) parts.Add("Alt");
            if (Shift) parts.Add("Shift");
            if (Win) parts.Add("Win");
            parts.Add(KeyName(VirtualKey));
            return string.Join("+", parts);
        }
    }

    internal static string KeyName(uint vk) =>
        vk switch
        {
            >= 0x70 and <= 0x87 => "F" + (vk - 0x6F).ToString(),
            >= 0x30 and <= 0x39 => ((char)vk).ToString(),
            >= 0x41 and <= 0x5A => ((char)vk).ToString(),
            _ => "0x" + vk.ToString("X2"),
        };

    internal string Serialize() => DisplayText;

    internal static bool TryParse(string? text, out HotkeyChoice choice)
    {
        choice = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        bool control = false, alt = false, shift = false, win = false;
        uint vk = 0;
        foreach (string rawPart in text.Split('+', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            switch (rawPart.ToUpperInvariant())
            {
                case "CTRL" or "CONTROL": control = true; break;
                case "ALT": alt = true; break;
                case "SHIFT": shift = true; break;
                case "WIN" or "WINDOWS": win = true; break;
                default:
                    if (!TryParseKey(rawPart, out vk))
                    {
                        return false;
                    }

                    break;
            }
        }

        if (vk == 0)
        {
            return false;
        }

        choice = new HotkeyChoice(control, alt, shift, win, vk);
        return true;
    }

    internal static bool TryParseKey(string text, out uint vk)
    {
        vk = 0;
        string upper = text.Trim().ToUpperInvariant();
        if (upper.Length == 1)
        {
            char c = upper[0];
            if (c is >= 'A' and <= 'Z')
            {
                vk = c;
                return true;
            }

            if (c is >= '0' and <= '9')
            {
                vk = c;
                return true;
            }
        }

        if (upper.StartsWith('F') && int.TryParse(upper[1..], out int fn) && fn is >= 1 and <= 24)
        {
            vk = (uint)(0x70 + fn - 1);
            return true;
        }

        return false;
    }

    /// <summary>Keys offered in the settings UI.</summary>
    internal static IReadOnlyList<(string Label, uint Vk)> KnownKeys
    {
        get
        {
            var keys = new List<(string, uint)>(26 + 10 + 12);
            for (uint vk = 0x41; vk <= 0x5A; vk++)
            {
                keys.Add(((char)vk + string.Empty, vk));
            }

            for (uint vk = 0x30; vk <= 0x39; vk++)
            {
                keys.Add(((char)vk + string.Empty, vk));
            }

            for (uint vk = 0x70; vk <= 0x7B; vk++)
            {
                keys.Add(("F" + (vk - 0x6F), vk));
            }

            return keys;
        }
    }
}

/// <summary>
/// Message-only window hosting WM_HOTKEY and tray callbacks. All callbacks are
/// dispatched synchronously on the window's (UI) thread.
/// </summary>
internal sealed class ShellMessageWindow : IDisposable
{
    private const string ClassName = "WSecret.ShellMessageWindow";
    private readonly Native.WndProcDelegate _wndProc;
    private readonly IntPtr _hwnd;
    private bool _disposed;

    internal ShellMessageWindow()
    {
        // Keep the delegate alive for the window's lifetime: the native side
        // holds a raw function pointer.
        _wndProc = WndProc;
        var wc = new Native.WNDCLASSEXW
        {
            cbSize = Marshal.SizeOf<Native.WNDCLASSEXW>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            lpszClassName = ClassName,
            hInstance = Native.GetModuleHandleW(null),
        };

        if (Native.RegisterClassExW(ref wc) == 0)
        {
            int error = Marshal.GetLastPInvokeError();
            if (error != 1410) // ERROR_CLASS_ALREADY_EXISTS (rebuilt after teardown)
            {
                throw new System.ComponentModel.Win32Exception(error, "RegisterClassExW failed.");
            }
        }

        _hwnd = Native.CreateWindowExW(0, ClassName, string.Empty, 0, 0, 0, 0, 0, (IntPtr)Native.HWND_MESSAGE, IntPtr.Zero, wc.hInstance, IntPtr.Zero);
        if (_hwnd == IntPtr.Zero)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "CreateWindowExW failed.");
        }
    }

    /// <summary>Raised with the hotkey id when the registered hotkey fires.</summary>
    internal event Action<int>? HotkeyPressed;

    /// <summary>Raised with the mouse message when the tray icon is clicked.</summary>
    internal event Action<uint>? TrayMouse;

    internal IntPtr Handle => _hwnd;

    private IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        switch (msg)
        {
            case Native.WM_HOTKEY:
                HotkeyPressed?.Invoke(wParam.ToInt32());
                return IntPtr.Zero;
            case Native.WM_TRAYICON:
                TrayMouse?.Invoke((uint)(lParam.ToInt64() & 0xFFFF));
                return IntPtr.Zero;
            default:
                return Native.DefWindowProcW(hWnd, msg, wParam, lParam);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_hwnd != IntPtr.Zero)
        {
            Native.DestroyWindow(_hwnd);
        }
    }
}

/// <summary>Register/unregister of the configurable global hotkey.</summary>
internal sealed class HotkeyRegistration : IDisposable
{
    internal const int HotkeyId = 0x57A1;

    private readonly IntPtr _hwnd;
    private bool _registered;

    internal HotkeyRegistration(IntPtr hwnd) => _hwnd = hwnd;

    internal HotkeyChoice? Current { get; private set; }

    /// <summary>
    /// Registers the hotkey, replacing any previous registration. On failure
    /// the previous registration is gone and <paramref name="win32Error"/> is
    /// set for visible reporting — never silently dropped.
    /// </summary>
    internal bool TryRegister(HotkeyChoice choice, out int win32Error)
    {
        Unregister();
        if (Native.RegisterHotKey(_hwnd, HotkeyId, choice.Modifiers, choice.VirtualKey))
        {
            _registered = true;
            Current = choice;
            win32Error = 0;
            return true;
        }

        win32Error = Marshal.GetLastPInvokeError();
        Current = null;
        return false;
    }

    internal void Unregister()
    {
        if (_registered)
        {
            Native.UnregisterHotKey(_hwnd, HotkeyId);
            _registered = false;
        }

        Current = null;
    }

    public void Dispose() => Unregister();
}

/// <summary>Tray icon with a native context menu. Commands are raised as events.</summary>
internal sealed class TrayIcon : IDisposable
{
    private const uint IconId = 1;
    private const uint CmdShow = 1001;
    private const uint CmdLock = 1002;
    private const uint CmdStartup = 1003;
    private const uint CmdExit = 1004;

    private readonly ShellMessageWindow _window;
    private readonly Func<bool> _startupEnabled;
    private readonly Func<bool> _canLock;
    private IntPtr _icon;
    private bool _added;

    internal TrayIcon(ShellMessageWindow window, string tooltip, Func<bool> startupEnabled, Func<bool> canLock)
    {
        _window = window;
        _startupEnabled = startupEnabled;
        _canLock = canLock;
        _icon = CreateAppIcon(32);
        _window.TrayMouse += OnTrayMouse;
        var data = BuildData(tooltip);
        _added = Native.Shell_NotifyIconW(Native.NIM_ADD, ref data);
        if (!_added)
        {
            int error = Marshal.GetLastPInvokeError();
            DestroyIcon();
            throw new System.ComponentModel.Win32Exception(error, "Shell_NotifyIconW(NIM_ADD) failed.");
        }
    }

    internal event Action? ShowRequested;
    internal event Action? LockRequested;
    internal event Action? ToggleStartupRequested;
    internal event Action? ExitRequested;

    internal void SetTooltip(string tooltip)
    {
        var data = BuildData(tooltip);
        data.uFlags = Native.NIF_TIP;
        Native.Shell_NotifyIconW(Native.NIM_MODIFY, ref data);
    }

    private Native.NOTIFYICONDATAW BuildData(string tooltip) => new()
    {
        cbSize = Marshal.SizeOf<Native.NOTIFYICONDATAW>(),
        hWnd = _window.Handle,
        uID = IconId,
        uFlags = Native.NIF_MESSAGE | Native.NIF_ICON | Native.NIF_TIP,
        uCallbackMessage = Native.WM_TRAYICON,
        hIcon = _icon,
        szTip = tooltip,
    };

    private void OnTrayMouse(uint mouseMessage)
    {
        switch (mouseMessage)
        {
            case Native.WM_LBUTTONUP:
            case Native.WM_LBUTTONDBLCLK:
                ShowRequested?.Invoke();
                break;
            case Native.WM_RBUTTONUP:
                ShowMenu();
                break;
        }
    }

    private void ShowMenu()
    {
        IntPtr menu = Native.CreatePopupMenu();
        if (menu == IntPtr.Zero)
        {
            return;
        }

        try
        {
            Native.AppendMenuW(menu, Native.MF_STRING, (IntPtr)CmdShow, "Show Quick Access");
            Native.AppendMenuW(menu, _canLock() ? Native.MF_STRING : Native.MF_STRING | Native.MF_GRAYED, (IntPtr)CmdLock, "Lock now");
            Native.AppendMenuW(menu, Native.MF_SEPARATOR, IntPtr.Zero, string.Empty);
            Native.AppendMenuW(menu, Native.MF_STRING | (_startupEnabled() ? Native.MF_CHECKED : 0), (IntPtr)CmdStartup, "Launch at sign-in");
            Native.AppendMenuW(menu, Native.MF_SEPARATOR, IntPtr.Zero, string.Empty);
            Native.AppendMenuW(menu, Native.MF_STRING, (IntPtr)CmdExit, "Exit");

            Native.GetCursorPos(out Native.POINT point);
            // Required by the shell before TrackPopupMenu so the menu dismisses
            // correctly on focus loss.
            Native.SetForegroundWindow(_window.Handle);
            uint command = Native.TrackPopupMenu(menu, Native.TPM_RIGHTBUTTON | Native.TPM_RETURNCMD | Native.TPM_NONOTIFY, point.x, point.y, 0, _window.Handle, IntPtr.Zero);
            switch (command)
            {
                case CmdShow:
                    ShowRequested?.Invoke();
                    break;
                case CmdLock:
                    LockRequested?.Invoke();
                    break;
                case CmdStartup:
                    ToggleStartupRequested?.Invoke();
                    break;
                case CmdExit:
                    ExitRequested?.Invoke();
                    break;
            }
        }
        finally
        {
            Native.DestroyMenu(menu);
        }
    }

    /// <summary>Loads the packaged multi-resolution application icon for the tray.</summary>
    private static IntPtr CreateAppIcon(int size)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Assets", "WSecret.ico");
        const uint imageIcon = 1;
        const uint loadFromFile = 0x00000010;
        const uint defaultSize = 0x00000040;
        IntPtr icon = Native.LoadImageW(IntPtr.Zero, path, imageIcon, size, size, loadFromFile | defaultSize);
        if (icon == IntPtr.Zero)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "LoadImageW failed for Assets/WSecret.ico.");
        }
        return icon;
    }

    private void DestroyIcon()
    {
        if (_icon != IntPtr.Zero)
        {
            Native.DestroyIcon(_icon);
            _icon = IntPtr.Zero;
        }
    }

    public void Dispose()
    {
        _window.TrayMouse -= OnTrayMouse;
        if (_added)
        {
            var data = BuildData(string.Empty);
            Native.Shell_NotifyIconW(Native.NIM_DELETE, ref data);
            _added = false;
        }

        DestroyIcon();
    }
}
