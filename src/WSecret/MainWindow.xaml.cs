using System.ComponentModel;
using System.IO;

using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

using Windows.ApplicationModel;
using Windows.Graphics;
using Windows.Storage;
using Windows.System;
using Windows.UI.Core;

using WinRT.Interop;

namespace WSecret;

/// <summary>
/// Quick Access shell window and controller. Owns the broker channel, the
/// native hosts (message window, global hotkey, tray) and all view state
/// transitions. SECURITY CONTRACT: only metadata ever reaches this class —
/// values, passphrases and TOTP codes live and die inside the broker process.
///
/// Stale-response rejection is enforced at three layers:
/// 1. BrokerClient drops responses whose generation is not the last known one;
/// 2. list/code updates apply only when <see cref="_listEpoch"/> is unchanged;
/// 3. detail updates apply only when <see cref="_selectionEpoch"/> is unchanged
///    and the shell is still unlocked.
/// </summary>
public sealed partial class MainWindow : Window, IShellActions
{
    private const string HotkeySettingsKey = "Hotkey";
    private const string StartupTaskId = "WSecretStartup";
    private const double MinWidthDip = 500;
    private const double MinHeightDip = 370;
    private const int InitialWidthDip = 580;
    private const int InitialHeightDip = 400;
    private const int MaxCodeEntries = 50;

    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _brokerGate = new(1, 1);
    private readonly DispatcherTimer _codeTicker;
    private readonly DispatcherTimer _searchDebounce;

    private BrokerClient? _broker;
    private ShellMessageWindow? _messages;
    private HotkeyRegistration? _hotkeys;
    private TrayIcon? _tray;

    private long _listEpoch;
    private long _selectionEpoch;
    private bool _showingTools;
    private string? _resultsQuery;
    // Populated only from a complete, unfiltered list for this unlock. Never cache values.
    private List<EntryItem>? _nameIndex;
    private MenuFlyout? _codeChooser;
    private bool _loaded;
    private bool _initializing = true;
    private bool _syncingView;
    private bool _codesRefreshRunning;
    private bool _exiting;

    public MainWindow()
    {
        VM = new ShellViewModel(this);
        InitializeComponent();

        // WinUI desktop does not guarantee an async SynchronizationContext.
        // Broker continuations update XAML and must resume on this dispatcher.
        SynchronizationContext.SetSynchronizationContext(
            new Microsoft.UI.Dispatching.DispatcherQueueSynchronizationContext(DispatcherQueue));

        // Not settable in XAML (WMC0612: the XBF generator has no schema for this
        // property on Window), so it is applied here as early as the XAML attribute was.
        ExtendsContentIntoTitleBar = true;

        _codeTicker = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _codeTicker.Tick += CodeTicker_Tick;
        _searchDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _searchDebounce.Tick += SearchDebounce_Tick;

        VM.PropertyChanged += VM_PropertyChanged;
        RootGrid.PreviewKeyDown += Palette_PreviewKeyDown;
        RootGrid.Loaded += RootGrid_Loaded;
    }

    public ShellViewModel VM { get; }

    // ---- window lifecycle ------------------------------------------------

    private void RootGrid_Loaded(object sender, RoutedEventArgs e)
    {
        if (_loaded)
        {
            return;
        }

        _loaded = true;

        SetTitleBar(DragRegion);

        IntPtr hwnd = WindowNative.GetWindowHandle(this);
        double scale = Native.GetDpiForWindow(hwnd) / 96.0;
        SizeInt32 size = new((int)(InitialWidthDip * scale), (int)(InitialHeightDip * scale));
        RectInt32 work = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        AppWindow.MoveAndResize(new RectInt32(work.X + (work.Width - size.Width) / 2,
            work.Y + (work.Height - size.Height) / 2, size.Width, size.Height));
        UpdateCaptionInset();
        RootGrid.XamlRoot.Changed += (_, _) => UpdateCaptionInset();
        AppWindow.Changed += AppWindow_Changed;
        AppWindow.Closing += AppWindow_Closing;

        // Native hosts: one message-only window feeds both WM_HOTKEY and tray
        // callbacks on the UI thread.
        _messages = new ShellMessageWindow();
        _messages.HotkeyPressed += OnHotkeyPressed;
        _hotkeys = new HotkeyRegistration(_messages.Handle);
        try
        {
            _tray = new TrayIcon(_messages, "WSecret Quick Access", () => VM.LaunchAtSignIn, () => VM.IsUnlocked);
            _tray.ShowRequested += () => DispatcherQueue.TryEnqueue(ShowShellSafe);
            _tray.LockRequested += () => DispatcherQueue.TryEnqueue(() => { if (VM.IsUnlocked) _ = LockAsync(); });
            _tray.ToggleStartupRequested += () => DispatcherQueue.TryEnqueue(() => _ = SetLaunchAtSignInAsync(!VM.LaunchAtSignIn));
            _tray.ExitRequested += () => DispatcherQueue.TryEnqueue(ExitApplication);
        }
        catch (Win32Exception ex)
        {
            VM.ShowError("Tray icon", ex.Message + " The window remains available normally.", warning: true);
        }

        foreach ((string label, uint _) in HotkeyChoice.KnownKeys)
        {
            HotkeyKeyBox.Items.Add(label);
        }

        HotkeyChoice choice = LoadHotkeySetting();
        HotkeyCtrl.IsChecked = choice.Control;
        HotkeyAlt.IsChecked = choice.Alt;
        HotkeyShift.IsChecked = choice.Shift;
        HotkeyWin.IsChecked = choice.Win;
        HotkeyKeyBox.SelectedIndex = IndexOfKey(choice.VirtualKey);
        RegisterHotkeyFromUi(reportSuccess: false);
        VM.HotkeyDisplayText = "Hotkey: " + choice.DisplayText;

        ClearClipboardSwitch.IsOn = VM.ClearClipboardOnLock;
        _ = LoadStartupStateAsync();

        _syncingView = true;
        ViewSelector.SelectedItem = DetailsTab;
        SetPanelVisibility(ShellView.Details);
        _syncingView = false;

        EditorActionBox.SelectedIndex = (int)WriteAction.NewRandom;
        StorePathText.Text = "Store: " + ResolveStorePath();
        ApplyStateChrome();

        _initializing = false;

        _ = StartBrokerAsync();
    }

    private void UpdateCaptionInset()
    {
        double scale = RootGrid.XamlRoot.RasterizationScale;
        CaptionInset.Width = AppWindow.TitleBar.RightInset / scale;
    }

    private void AppWindow_Changed(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (!args.DidSizeChange)
        {
            return;
        }

        IntPtr hwnd = WindowNative.GetWindowHandle(this);
        double scale = Native.GetDpiForWindow(hwnd) / 96.0;
        int minWidth = (int)(MinWidthDip * scale);
        int minHeight = (int)(MinHeightDip * scale);
        SizeInt32 size = sender.Size;
        if (size.Width < minWidth || size.Height < minHeight)
        {
            sender.Resize(new SizeInt32(Math.Max(size.Width, minWidth), Math.Max(size.Height, minHeight)));
        }
    }

    private void AppWindow_Closing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_exiting)
        {
            return;
        }

        // Close hides to the tray; only the tray Exit command terminates.
        args.Cancel = true;
        HideToTray();
    }

    /// <summary>Foregrounds the window (launch activation, hotkey, tray, redirect).</summary>
    internal void ShowFromAnywhere()
    {
        AppWindow.Show();
        IntPtr hwnd = WindowNative.GetWindowHandle(this);
        Native.ShowWindow(hwnd, Native.SW_RESTORE);
        Native.SetActiveWindow(hwnd);
        Native.SetForegroundWindow(hwnd);
        DispatcherQueue.TryEnqueue(() =>
        {
            ShowSearch();
            if (VM.IsUnlocked) SearchBox.SelectAll();
        });
    }

    private void ShowSearch()
    {
        if (!VM.IsUnlocked) return;
        Interlocked.Increment(ref _selectionEpoch);
        _codeChooser?.Hide();
        PaletteFeedback.Visibility = Visibility.Collapsed;
        SettingsButton.Flyout?.Hide();
        _showingTools = false;
        ApplyWorkspace();
        SearchBox.Focus(FocusState.Programmatic);
    }

    private void ShowShellSafe() => App.ShowShell();

    private void HideToTray()
    {
        Interlocked.Increment(ref _selectionEpoch);
        _codeChooser?.Hide();
        _codeTicker.Stop();
        AppWindow.Hide();
    }

    private async void ExitApplication()
    {
        if (_exiting)
        {
            return;
        }

        _exiting = true;
        _codeTicker.Stop();
        _searchDebounce.Stop();
        _lifetime.Cancel();

        BrokerClient? broker = _broker;
        _broker = null;
        if (broker is not null)
        {
            try
            {
                await broker.DisposeAsync();
            }
            catch (Exception)
            {
                // Teardown is best effort; pipe EOF locks and wipes the broker.
            }
        }

        _tray?.Dispose();
        _hotkeys?.Dispose();
        _messages?.Dispose();
        Application.Current.Exit();
    }

    // ---- broker orchestration -------------------------------------------

    private static string ResolveBrokerPath()
    {
        string baseDir;
        try
        {
            baseDir = Package.Current.InstalledLocation.Path;
        }
        catch (Exception)
        {
            baseDir = AppContext.BaseDirectory;
        }

        return Path.Combine(baseDir, "wsecret-broker.exe");
    }

    /// <summary>
    /// Mirrors the broker's store resolution (wsecret-cli/upstream s_set_path):
    /// --store (broker arg), else nonempty %SECRET_STORE%, else %HOME%\.secret,
    /// else %USERPROFILE%\.secret, else \.secret. Display only — the broker is
    /// authoritative and exits 2 at startup for paths outside 2..=1023 bytes.
    /// </summary>
    private static string ResolveStorePath()
    {
        string? env = Environment.GetEnvironmentVariable("SECRET_STORE");
        if (!string.IsNullOrEmpty(env))
        {
            return env;
        }

        string? home = Environment.GetEnvironmentVariable("HOME");
        if (!string.IsNullOrEmpty(home))
        {
            return Path.Combine(home, ".secret");
        }

        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return string.IsNullOrEmpty(profile)
            ? Path.DirectorySeparatorChar + ".secret"
            : Path.Combine(profile, ".secret");
    }

    private async Task StartBrokerAsync()
    {
        await _brokerGate.WaitAsync(_lifetime.Token);
        try
        {
            await StartBrokerCoreAsync();
        }
        finally
        {
            _brokerGate.Release();
        }
    }

    private async Task StartBrokerCoreAsync()
    {
        VM.ClearError();
        VM.StatusText = "Starting broker…";
        Interlocked.Increment(ref _listEpoch);
        Interlocked.Increment(ref _selectionEpoch);
        VM.BrokerConnected = false;
        ApplyLifecycle(BrokerLifecycle.Locked, VM.Hello, null);
        try
        {
            BrokerClient? old = _broker;
            _broker = null;
            if (old is not null)
            {
                await old.DisposeAsync();
            }
        }
        catch (Exception)
        {
        }

        try
        {
            BrokerClient broker = await BrokerClient.StartAsync(ResolveBrokerPath(), ResolveStorePath(), _lifetime.Token);
            _broker = broker;
            broker.Disconnected += () => DispatcherQueue.TryEnqueue(() =>
                _ = HandleChannelLostAsync(new IOException("The secure broker stopped."), broker));
            VM.BrokerConnected = true;
            VM.StatusText = "Broker started; refreshing state…";

            HelloInfo hello = await broker.HelloAsync(_lifetime.Token);
            VM.ApplyBrokerState(hello.Lifecycle, hello.Hello, hello.Caps);
            VM.StatusText = "Broker connected.";
            if (hello.Lifecycle == BrokerLifecycle.Unlocked)
            {
                await RefreshAsync();
            }
        }
        catch (BrokerLaunchException ex)
        {
            VM.BrokerConnected = false;
            VM.State = BrokerLifecycle.Locked;
            VM.ShowError("Broker unavailable", ex.Message + " Use “Retry broker” to try again.");
        }
        catch (OperationCanceledException ex)
        {
            if (!_lifetime.IsCancellationRequested)
            {
                VM.BrokerConnected = false;
                VM.ShowError("Broker unavailable", ex.Message + " Use “Retry broker” to try again.");
            }
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex);
        }
        catch (Exception ex)
        {
            VM.BrokerConnected = false;
            VM.State = BrokerLifecycle.Locked;
            VM.ShowError("Broker unavailable", ex.GetType().Name + ": " + ex.Message + " Use “Retry broker” to try again.");
        }
    }

    private async Task RefreshLifecycleAsync(BrokerClient broker)
    {
        if (!ReferenceEquals(_broker, broker))
        {
            return;
        }
        try
        {
            PingInfo ping = await broker.PingAsync(_lifetime.Token);
            if (ReferenceEquals(_broker, broker))
            {
                ApplyLifecycle(ping.Lifecycle, ping.Hello, null);
            }
        }
        catch (Exception)
        {
            // Lifecycle display stays as-is; the operation's own error path reports.
        }
    }

    private void ApplyLifecycle(BrokerLifecycle lifecycle, HelloState hello, BrokerCaps? caps)
    {
        if (VM.State != lifecycle)
        {
            // Any lifecycle transition invalidates everything in flight.
            Interlocked.Increment(ref _listEpoch);
            Interlocked.Increment(ref _selectionEpoch);
        }

        VM.ApplyBrokerState(lifecycle, hello, caps);
        if (lifecycle == BrokerLifecycle.Locked)
        {
            VM.ResetForLock();
            _nameIndex = null;
            _searchDebounce.Stop();
            SearchBox.Text = EditorNameBox.Text = EditorNewNameBox.Text = EditorSubkeysBox.Text = string.Empty;
            VM.SearchText = VM.EditorNameText = VM.EditorNewNameText = VM.EditorSubkeysText = string.Empty;
            _resultsQuery = null;
        }
    }

    private async Task HandleChannelLostAsync(Exception ex, BrokerClient? expected = null)
    {
        if (expected is not null && !ReferenceEquals(_broker, expected))
        {
            return; // A superseded broker must not disconnect its replacement.
        }

        VM.BrokerConnected = false;
        ApplyLifecycle(BrokerLifecycle.Locked, VM.Hello, null);
        VM.StatusText = "Broker disconnected.";
        VM.ShowError("Broker channel lost", ex.Message + " Use “Retry broker” to reconnect.");
        await Task.CompletedTask;
    }

    // ---- IShellActions ---------------------------------------------------

    public async Task UnlockAsync(bool withHello)
    {
        await _brokerGate.WaitAsync(_lifetime.Token);
        try
        {
            await UnlockCoreAsync(withHello);
        }
        finally
        {
            _brokerGate.Release();
        }
    }

    private async Task UnlockCoreAsync(bool withHello)
    {
        BrokerClient? broker = _broker;
        if (broker is null)
        {
            VM.ShowError("Broker unavailable", "Start the broker first (Retry broker).");
            return;
        }

        VM.ClearError();
        VM.State = BrokerLifecycle.Unlocking;
        VM.StatusText = withHello
            ? "Waiting for Windows Hello verification…"
            : "Waiting for the broker's secure masked prompt…";
        try
        {
            await broker.UnlockAsync(withHello ? UnlockMode.HelloPrf : UnlockMode.BrokerPrompt, _lifetime.Token);
            if (!ReferenceEquals(_broker, broker))
            {
                return;
            }
            await RefreshLifecycleAsync(broker);
            VM.StatusText = "Unlocked.";
            await RefreshAsync();
        }
        catch (OperationCanceledException)
        {
            await RefreshLifecycleAsync(broker);
            VM.StatusText = "Unlock cancelled.";
        }
        catch (BrokerRequestException ex)
        {
            await RefreshLifecycleAsync(broker);
            VM.ShowError("Unlock failed", ex.Message);
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex, broker);
        }
    }

    public async Task LockAsync()
    {
        await _brokerGate.WaitAsync(_lifetime.Token);
        try
        {
            await LockCoreAsync();
        }
        finally
        {
            _brokerGate.Release();
        }
    }

    private async Task LockCoreAsync()
    {
        BrokerClient? broker = _broker;
        if (broker is null)
        {
            return;
        }

        VM.State = BrokerLifecycle.Locking;
        Interlocked.Increment(ref _listEpoch);
        Interlocked.Increment(ref _selectionEpoch);
        try
        {
            await broker.LockAsync(VM.ClearClipboardOnLock, _lifetime.Token);
            if (!ReferenceEquals(_broker, broker))
            {
                return;
            }
            ApplyLifecycle(BrokerLifecycle.Locked, VM.Hello, null);
            VM.StatusText = "Locked.";
        }
        catch (OperationCanceledException)
        {
            await RefreshLifecycleAsync(broker);
        }
        catch (BrokerRequestException ex)
        {
            await RefreshLifecycleAsync(broker);
            VM.ShowError("Lock failed", ex.Message);
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex, broker);
        }
    }

    public Task RefreshAsync()
    {
        _nameIndex = null;
        return RefreshResultsAsync();
    }

    private async Task RefreshResultsAsync()
    {
        BrokerClient? broker = _broker;
        if (broker is null || !VM.IsUnlocked)
        {
            return;
        }

        long listEpoch = Interlocked.Increment(ref _listEpoch);
        CancellationToken token = _lifetime.Token;
        try
        {
            byte[]? needle = EncodeNeedle(VM.SearchText);
            if (needle is null)
            {
                // No name can contain a needle longer than 255 bytes.
                VM.Results.Clear();
                _resultsQuery = VM.SearchText;
                UpdateResultActions();
                VM.Codes.Clear();
                VM.EntryCountText = "0 entries";
                VM.StatusText = "No entries match.";
                return;
            }

            uint total;
            List<EntryItem> entries;
            if (_nameIndex is { } index)
            {
                entries = needle.Length == 0 ? index : index.FindAll(item => ContainsName(item.RawName, needle));
                total = (uint)entries.Count;
            }
            else
            {
                var page = await broker.ListAllAsync(needle, token);
                if (listEpoch != Interlocked.Read(ref _listEpoch) || !VM.IsUnlocked) return;
                total = page.Total;
                entries = page.Entries.ConvertAll(static info => new EntryItem(info));
                // On a truncated page, the next query still searches the whole store.
                if (needle.Length == 0 && entries.Count == total) _nameIndex = entries;
            }

            EntryItem? previous = _resultsQuery == VM.SearchText ? VM.SelectedEntry : null;
            int next = entries.Count == 0 ? -1 : 0;
            _resultsQuery = null;
            VM.Results.Clear();
            foreach (EntryItem item in entries)
            {
                if (previous is not null && item.Slot == previous.Slot &&
                    item.RawName.AsSpan().SequenceEqual(previous.RawName))
                    next = VM.Results.Count;
                VM.Results.Add(item);
            }

            _resultsQuery = VM.SearchText;
            ResultsList.SelectedIndex = next;
            UpdateResultActions();
            VM.EntryCountText = entries.Count == total
                ? $"{entries.Count} entries"
                : $"{entries.Count} / {total} entries";
            VM.StatusText = $"Refreshed {entries.Count} entries.";
            if (_showingTools && VM.ActiveView == ShellView.Codes)
                await RefreshCodesAsync(broker, listEpoch, token);
        }
        catch (OperationCanceledException)
        {
        }
        catch (BrokerRequestException ex)
        {
            if (listEpoch == Interlocked.Read(ref _listEpoch))
            {
                VM.ShowError("Refresh failed", ex.Message, warning: true);
            }
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex, broker);
        }
    }

    private static bool ContainsName(ReadOnlySpan<byte> name, ReadOnlySpan<byte> needle)
    {
        // Match broker List: ASCII case folding over raw bytes, including '/'.
        static byte Fold(byte b) => b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
        for (int i = 0; i <= name.Length - needle.Length; i++)
        {
            int j = 0;
            while (j < needle.Length && Fold(name[i + j]) == Fold(needle[j])) j++;
            if (j == needle.Length) return true;
        }
        return false;
    }

    private async Task RefreshCodesAsync(BrokerClient broker, long listEpoch, CancellationToken token)
    {
        var codeEntries = VM.Results.Where(row => NameCodec.IsAutoIndexedCodeName(row.RawName))
            .Take(MaxCodeEntries).Select(row => row.Info).ToArray();
        var items = new List<CodeItem>(codeEntries.Length);
        foreach (EntryInfo info in codeEntries)
        {
            try
            {
                EntryDetail detail = await broker.MetaAsync(info.RawName, token);
                if (detail.IsCode)
                {
                    items.Add(new CodeItem(info, detail.CodeRemainingSeconds));
                }
            }
            catch (Exception)
            {
                // One unreadable entry must not break the Codes view.
            }
        }

        if (listEpoch != Interlocked.Read(ref _listEpoch) || !VM.IsUnlocked || !_showingTools || VM.ActiveView != ShellView.Codes)
        {
            return;
        }

        VM.Codes.Clear();
        foreach (CodeItem item in items)
        {
            VM.Codes.Add(item);
        }
    }

    public Task CopySelectedAsync() => CopyCoreAsync(VM.SelectedEntry, CopyMode.Auto);

    public Task CopyCodeAsync(EntryItem? entry) => entry is null
        ? CopySelectedCodeAsync() : CopyCoreAsync(entry, CopyMode.Code);

    private async Task CopySelectedCodeAsync()
    {
        if (VM.SelectedEntry is not { } selected || _broker is not { } broker || !HasCurrentSelection) return;
        long epoch = _selectionEpoch;
        try
        {
            List<EntryInfo> targets = await broker.CodeTargetsAsync(selected.Info, _lifetime.Token);
            if (!HasCurrentSelection || epoch != _selectionEpoch || !ReferenceEquals(broker, _broker)) return;
            if (targets.Count == 0)
            {
                CodeAction.IsEnabled = CopyCodeButton.IsEnabled = false;
                ShowFeedback("No authenticator code is linked to this item.");
                return;
            }
            if (targets.Count == 1)
            {
                await CopyCoreAsync(new EntryItem(targets[0]), CopyMode.Code);
                return;
            }

            // Never guess between two accounts or pick the first matching label.
            _codeChooser?.Hide();
            var chooser = new MenuFlyout();
            foreach (EntryInfo target in targets)
            {
                var item = new MenuFlyoutItem { Text = target.DisplayName };
                item.Click += async (_, _) =>
                {
                    if (HasCurrentSelection && epoch == _selectionEpoch && ReferenceEquals(broker, _broker))
                        await CopyCoreAsync(new EntryItem(target), CopyMode.Code);
                };
                chooser.Items.Add(item);
            }
            _codeChooser = chooser;
            chooser.Closed += (_, _) => { if (_codeChooser == chooser) _codeChooser = null; };
            chooser.ShowAt(_showingTools ? CopyCodeButton : CodeAction);
        }
        catch (BrokerRequestException ex) { VM.ShowError("Code unavailable", ex.Message, warning: true); }
        catch (IOException ex) { await HandleChannelLostAsync(ex, broker); }
        catch (OperationCanceledException) { }
    }

    private async Task CopyCoreAsync(EntryItem? entry, CopyMode mode)
    {
        BrokerClient? broker = _broker;
        if (broker is null || entry is null || !VM.IsUnlocked)
        {
            return;
        }

        long epoch = _selectionEpoch;
        bool dismiss = !_showingTools;
        try
        {
            CopyOutcome outcome = mode == CopyMode.Code
                ? await broker.CodeAsync(entry.Info, _lifetime.Token)
                : await broker.CopyAsync(entry.Info, mode, _lifetime.Token);
            if (VM.IsUnlocked && ReferenceEquals(broker, _broker) && epoch == _selectionEpoch)
            {
                ShowFeedback($"Copied. Clipboard clears in {Math.Max(1, (int)(outcome.ClipboardTtlMs / 1000))} s.");
                if (dismiss)
                {
                    await Task.Delay(350);
                    if (VM.IsUnlocked && !_showingTools && epoch == _selectionEpoch) HideToTray();
                }
            }
        }
        catch (BrokerRequestException ex)
        {
            VM.ShowError("Copy failed", ex.Message, warning: true);
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex, broker);
        }
        catch (OperationCanceledException) { }
    }

    public void OnSelectionChanged(EntryItem? entry)
    {
        Interlocked.Increment(ref _selectionEpoch);
        _codeChooser?.Hide();
        PaletteFeedback.Visibility = Visibility.Collapsed;
        UpdateResultActions();
        if (_showingTools && VM.ActiveView == ShellView.Details) _ = LoadDetailsAsync(entry);
    }

    private async Task LoadDetailsAsync(EntryItem? entry)
    {
        long selectionEpoch = Interlocked.Increment(ref _selectionEpoch);
        if (entry is null)
        {
            VM.SelectedDisplayName = string.Empty;
            VM.SelectedMetaText = "Select an entry to see its details.";
            return;
        }

        VM.SelectedDisplayName = entry.DisplayName;
        VM.SelectedMetaText = "Loading metadata…";
        BrokerClient? broker = _broker;
        if (broker is null)
        {
            return;
        }

        try
        {
            EntryDetail detail = await broker.MetaAsync(entry.RawName, _lifetime.Token);
            if (selectionEpoch != Interlocked.Read(ref _selectionEpoch) || !VM.IsUnlocked)
            {
                return; // stale response: selection or lifecycle changed
            }

            VM.SelectedMetaText = detail.Slot == entry.Slot
                ? BuildMetaText(entry, detail) : "This record changed or its name is ambiguous. Refresh before acting.";
        }
        catch (BrokerRequestException ex)
        {
            if (selectionEpoch == Interlocked.Read(ref _selectionEpoch))
            {
                VM.SelectedMetaText = ex.Message;
            }
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex, broker);
        }
    }

    private static string BuildMetaText(EntryItem entry, EntryDetail detail)
    {
        string kind = detail.IsCode ? "Code (TOTP)" : "Secret";
        string text = $"{kind} · slot {detail.Slot} · value {detail.ValueLength} bytes · name {entry.RawName.Length} bytes (raw identity)";
        if (detail.IsCode)
        {
            text += $" · next code in {detail.CodeRemainingSeconds} s";
        }

        return text;
    }

    public Task EditSelectedAsync()
    {
        EntryItem? entry = VM.SelectedEntry;
        if (entry is null)
        {
            return Task.CompletedTask;
        }

        SelectView(ShellView.Editor);
        VM.EditorAction = WriteAction.ReplaceTypedValue;
        EditorActionBox.SelectedIndex = (int)WriteAction.ReplaceTypedValue;
        VM.EditorNameText = entry.DisplayName;
        EditorNameBox.Text = entry.DisplayName;
        VM.EditorResultText = "Edit: the new value is entered in the broker's masked prompt.";
        return Task.CompletedTask;
    }

    public async Task RenewSelectedAsync()
    {
        EntryItem? entry = VM.SelectedEntry;
        BrokerClient? broker = _broker;
        if (entry is null || broker is null)
        {
            return;
        }

        await RunWriteAsync(() => broker.UpdateAsync(entry.Slot, entry.RawName, null, UpdateMode.Renew, _lifetime.Token), "Renew");
    }

    public async Task TombstoneSelectedAsync()
    {
        EntryItem? entry = VM.SelectedEntry;
        BrokerClient? broker = _broker;
        if (entry is null || broker is null)
        {
            return;
        }

        byte[] tombstoneName = TombstoneName(entry.RawName);
        await RunWriteAsync(() => broker.UpdateAsync(entry.Slot, entry.RawName, tombstoneName, UpdateMode.RenameOnly, _lifetime.Token), "Tombstone");
    }

    private static byte[] TombstoneName(byte[] rawName)
    {
        byte[] prefix = "DELETED:"u8.ToArray();
        byte[] result = new byte[prefix.Length + rawName.Length];
        prefix.CopyTo(result, 0);
        rawName.CopyTo(result, prefix.Length);
        return result;
    }

    public async Task ApplyEditorAsync()
    {
        BrokerClient? broker = _broker;
        if (broker is null || !VM.IsUnlocked)
        {
            return;
        }

        byte[] name;
        try
        {
            name = ResolveEditorName();
        }
        catch (ArgumentException ex)
        {
            VM.ShowError("Invalid name", ex.Message, warning: true);
            return;
        }

        try
        {
            Task<WriteOutcome> write = VM.EditorAction switch
            {
                WriteAction.NewRandom => broker.NewAsync(name, deterministic: false, Array.Empty<byte[]>(), _lifetime.Token),
                WriteAction.NewDeterministic => broker.NewAsync(name, deterministic: true, ParseSubkeys(VM.EditorSubkeysText), _lifetime.Token),
                WriteAction.SetTypedValue => broker.SetAsync(name, _lifetime.Token),
                WriteAction.ReplaceTypedValue => broker.UpdateAsync(ExpectSlotFor(name), name, null, UpdateMode.PromptValue, _lifetime.Token),
                WriteAction.RenameOnly => broker.UpdateAsync(ExpectSlotFor(name), name, ParseNewName(), UpdateMode.RenameOnly, _lifetime.Token),
                WriteAction.Renew => broker.UpdateAsync(ExpectSlotFor(name), name, null, UpdateMode.Renew, _lifetime.Token),
                WriteAction.Tombstone => broker.UpdateAsync(ExpectSlotFor(name), name, TombstoneName(name), UpdateMode.RenameOnly, _lifetime.Token),
                _ => throw new InvalidOperationException("Unknown editor action."),
            };

            await RunWriteAsync(() => write, "Write");
        }
        catch (ArgumentException ex)
        {
            VM.ShowError("Invalid input", ex.Message, warning: true);
        }
    }

    /// <summary>
    /// Resolves the editor name to exact raw bytes. When the editor text still
    /// matches the selected entry's display, the entry's original raw bytes are
    /// used so non-UTF-8 names keep their byte identity.
    /// </summary>
    private byte[] ResolveEditorName()
    {
        EntryItem? selected = VM.SelectedEntry;
        if (selected is not null && selected.DisplayName == VM.EditorNameText)
        {
            return selected.RawName;
        }

        return NameCodec.FromDisplayString(VM.EditorNameText);
    }

    private byte[] ParseNewName()
    {
        if (string.IsNullOrEmpty(VM.EditorNewNameText))
        {
            throw new ArgumentException("A new name is required for a rename.");
        }

        return NameCodec.FromDisplayString(VM.EditorNewNameText);
    }

    /// <summary>
    /// Parses deterministic components, one per line. Components may legally
    /// contain commas and may NOT contain any byte ≤ 0x20 (upstream s_keylen
    /// rule), so line breaks are the only separator; blank lines are ignored.
    /// </summary>
    private static List<byte[]> ParseSubkeys(string text)
    {
        var subkeys = new List<byte[]>();
        foreach (string line in text.Split('\n'))
        {
            string component = line.Trim('\r', ' ', '\t');
            if (component.Length == 0)
            {
                continue;
            }

            byte[] bytes = NameCodec.Utf8Bytes(component);
            if (bytes.Length > NameCodec.MaxNameBytes)
            {
                throw new ArgumentException("A component exceeds 255 UTF-8 bytes.");
            }

            foreach (byte b in bytes)
            {
                if (b <= 0x20)
                {
                    throw new ArgumentException("Components must not contain whitespace or control bytes.");
                }
            }

            subkeys.Add(bytes);
        }

        return subkeys;
    }

    /// <summary>Compare-and-swap guard: only when the editor targets the selection.</summary>
    private ulong ExpectSlotFor(byte[] name)
    {
        EntryItem? selected = VM.SelectedEntry;
        return selected is not null && selected.RawName.AsSpan().SequenceEqual(name) ? selected.Slot : 0;
    }

    private async Task RunWriteAsync(Func<Task<WriteOutcome>> write, string operation)
    {
        BrokerClient? broker = _broker;
        if (broker is null)
        {
            return;
        }

        try
        {
            WriteOutcome outcome = await write();
            VM.EditorResultText = DescribeWriteOutcome(outcome);
            VM.StatusText = operation + ": " + VM.EditorResultText;
            Interlocked.Increment(ref _listEpoch);
            await RefreshAsync();
        }
        catch (BrokerRequestException ex)
        {
            if (ex.Status is BrokerStatus.Conflict)
            {
                VM.ShowError(operation + " conflict", ex.Message + " Refresh and try again.");
                Interlocked.Increment(ref _listEpoch);
                await RefreshAsync();
            }
            else if (ex.Status is BrokerStatus.CommitUncertain)
            {
                VM.ShowError(operation + " uncertain", ex.Message + " Refresh before retrying.");
                Interlocked.Increment(ref _listEpoch);
                await RefreshAsync();
            }
            else if (ex.Status is BrokerStatus.ClipboardError && ex.Aux == (ushort)CommitState.Committed)
            {
                VM.EditorResultText = "Saved; secure clipboard copy failed.";
                VM.StatusText = operation + ": " + VM.EditorResultText;
                VM.ShowError(operation + " saved; copy failed", ex.Message, warning: true);
                Interlocked.Increment(ref _listEpoch);
                await RefreshAsync();
            }
            else
            {
                VM.ShowError(operation + " failed", ex.Message, warning: true);
            }
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex, broker);
        }
    }

    private static string DescribeWriteOutcome(WriteOutcome outcome)
    {
        string message = outcome.Commit switch
        {
            CommitState.Committed => "Saved.",
            CommitState.NotCommitted => "Nothing was written (store unchanged).",
            CommitState.Unknown => "Commit outcome uncertain — refresh before retrying.",
            _ => "Done.",
        };

        if (outcome.Commit == CommitState.Committed && outcome.WarnBits != 0)
        {
            if ((outcome.WarnBits & 0x4) != 0)
            {
                message += " Saved (recovered from a crashed writer; no store-integrity claim).";
            }

            if ((outcome.WarnBits & 0x3) != 0)
            {
                message += " Saved (status reporting failed).";
            }
        }

        if (outcome.ClipboardTtlMs > 0)
        {
            message += $" The generated value is on the broker's secure clipboard (clears in {Math.Max(1, (int)(outcome.ClipboardTtlMs / 1000))} s).";
        }

        return message;
    }

    public async Task EnrollHelloAsync()
    {
        BrokerClient? broker = _broker;
        if (broker is null)
        {
            return;
        }

        try
        {
            HelloStateResult result = await broker.HelloEnrollAsync(_lifetime.Token);
            VM.Hello = result.Hello;
            VM.StatusText = VM.HelloStateText;
        }
        catch (BrokerRequestException ex)
        {
            VM.ShowError("Hello enrollment failed", ex.Message, warning: true);
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex, broker);
        }
    }

    public async Task ForgetHelloAsync()
    {
        BrokerClient? broker = _broker;
        if (broker is null)
        {
            return;
        }

        try
        {
            HelloStateResult result = await broker.HelloForgetAsync(_lifetime.Token);
            VM.Hello = result.Hello;
            VM.StatusText = VM.HelloStateText;
        }
        catch (BrokerRequestException ex)
        {
            VM.ShowError("Hello forget failed", ex.Message, warning: true);
        }
        catch (IOException ex)
        {
            await HandleChannelLostAsync(ex, broker);
        }
    }

    public Task RetryBrokerAsync() => StartBrokerAsync();

    public void OnSearchTextChanged(string text)
    {
        if (!VM.IsUnlocked) return;
        _resultsQuery = null;
        ResultsList.SelectedIndex = -1;
        UpdateResultActions();
        VM.SearchText = text;
        Interlocked.Increment(ref _listEpoch);
        _searchDebounce.Stop();
        if (_nameIndex is not null) _ = RefreshResultsAsync();
        else _searchDebounce.Start();
    }

    public void SetActiveView(ShellView view) => SelectView(view);

    private void SelectView(ShellView view)
    {
        if (!VM.IsUnlocked) return;
        SettingsButton.Flyout?.Hide();
        _codeChooser?.Hide();
        _showingTools = true;
        _syncingView = true;
        VM.SetActiveView(view);
        ViewSelector.SelectedItem = view switch
        {
            ShellView.Codes => CodesTab,
            ShellView.Editor => EditorTab,
            _ => DetailsTab,
        };
        SetPanelVisibility(view);
        _syncingView = false;
        ApplyWorkspace();
        if (view == ShellView.Details) _ = LoadDetailsAsync(VM.SelectedEntry);
        if (view == ShellView.Codes && _broker is { } broker)
            _ = RefreshCodesAsync(broker, _listEpoch, _lifetime.Token);
        ViewSelector.Focus(FocusState.Programmatic);
    }

    private void SetPanelVisibility(ShellView view)
    {
        DetailsPanel.Visibility = ToVisibility(view == ShellView.Details);
        CodesPanel.Visibility = ToVisibility(view == ShellView.Codes);
        EditorPanel.Visibility = ToVisibility(view == ShellView.Editor);
    }

    // ---- timers ----------------------------------------------------------

    private void SearchDebounce_Tick(object? sender, object e)
    {
        _searchDebounce.Stop();
        _ = RefreshResultsAsync();
    }

    private void CodeTicker_Tick(object? sender, object e)
    {
        bool anyExpired = false;
        foreach (CodeItem item in VM.Codes)
        {
            item.Tick();
            if (item.SecondsLeft == 0)
            {
                anyExpired = true;
            }
        }

        if (anyExpired && !_codesRefreshRunning && VM.IsUnlocked)
        {
            _ = RefreshCodeCountdownsAsync();
        }
    }

    private async Task RefreshCodeCountdownsAsync()
    {
        BrokerClient? broker = _broker;
        if (broker is null)
        {
            return;
        }

        _codesRefreshRunning = true;
        try
        {
            foreach (CodeItem item in VM.Codes.ToArray())
            {
                try
                {
                    EntryDetail detail = await broker.MetaAsync(item.Info.RawName, _lifetime.Token);
                    if (!VM.IsUnlocked)
                    {
                        return;
                    }

                    item.RefreshRemaining(detail.CodeRemainingSeconds);
                }
                catch (Exception)
                {
                    // Countdown stays until the next refresh; nothing secret here.
                }
            }
        }
        finally
        {
            _codesRefreshRunning = false;
        }
    }

    // ---- VM chrome -------------------------------------------------------

    private void VM_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(ShellViewModel.State):
                ApplyStateChrome();
                break;
            case nameof(ShellViewModel.ErrorIsWarning):
                ShellInfoBar.Severity = VM.ErrorIsWarning ? InfoBarSeverity.Warning : InfoBarSeverity.Error;
                break;
        }
    }

    private void ApplyStateChrome()
    {
        if (!VM.IsUnlocked)
        {
            _showingTools = false;
            _codeChooser?.Hide();
            PaletteFeedback.Visibility = Visibility.Collapsed;
        }
        LockedHero.Visibility = ToVisibility(!VM.IsUnlocked);
        ApplyWorkspace();
        if (VM.IsUnlocked) DispatcherQueue.TryEnqueue(ShowSearch);
        Title = VM.WindowTitle;
        _tray?.SetTooltip("WSecret Quick Access — " + VM.StateLabel);
    }

    private bool HasCurrentSelection => VM.IsUnlocked && _resultsQuery == SearchBox.Text && VM.SelectedEntry is not null;

    private void ApplyWorkspace()
    {
        SearchPane.Visibility = ShortcutFooter.Visibility = ToVisibility(VM.IsUnlocked && !_showingTools);
        SecondaryPane.Visibility = ToVisibility(VM.IsUnlocked && _showingTools);
        if (VM.IsUnlocked && _showingTools && VM.ActiveView == ShellView.Codes)
            _codeTicker.Start();
        else
            _codeTicker.Stop();
        UpdateResultActions();
    }

    private void UpdateResultActions()
    {
        bool ready = HasCurrentSelection;
        PrimaryAction.IsEnabled = CodeAction.IsEnabled = OpenAction.IsEnabled = CopyCodeButton.IsEnabled = ready;
        PrimaryActionLabel.Text = VM.SelectedEntry?.IsCode == true ? "Copy code" : "Copy password";
        EmptyResults.Visibility = ToVisibility(VM.IsUnlocked && _resultsQuery == SearchBox.Text && VM.Results.Count == 0);
    }

    private void ShowFeedback(string message)
    {
        VM.StatusText = PaletteFeedback.Text = message;
        PaletteFeedback.Visibility = Visibility.Visible;
    }

    private static Visibility ToVisibility(bool visible) => visible ? Visibility.Visible : Visibility.Collapsed;

    // ---- XAML events -----------------------------------------------------

    private void LockUnlock_Click(object sender, RoutedEventArgs e)
    {
        if (VM.IsUnlocked)
        {
            _ = LockAsync();
        }
        else if (VM.IsLocked)
        {
            _ = UnlockAsync(withHello: false);
        }
    }

    private void BackToSearch_Click(object sender, RoutedEventArgs e) => ShowSearch();
    private void ShowCodes_Click(object sender, RoutedEventArgs e) => SelectView(ShellView.Codes);
    private void ShowEditor_Click(object sender, RoutedEventArgs e) => SelectView(ShellView.Editor);
    private void OpenItem_Click(object sender, RoutedEventArgs e)
    {
        if (HasCurrentSelection) SelectView(ShellView.Details);
    }

    private void PrimaryAction_Click(object sender, RoutedEventArgs e)
    {
        if (HasCurrentSelection) _ = CopySelectedAsync();
    }

    private void CodeAction_Click(object sender, RoutedEventArgs e) => _ = CopySelectedCodeAsync();

    private void Result_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        DependencyObject? source = e.OriginalSource as DependencyObject;
        while (source is not null && source is not ListViewItem && source != ResultsList)
            source = VisualTreeHelper.GetParent(source);
        if (HasCurrentSelection && source is ListViewItem row && ResultsList.ItemFromContainer(row) == VM.SelectedEntry)
        {
            SelectView(ShellView.Details);
            e.Handled = true;
        }
    }

    private void ShellInfoBar_Closed(InfoBar sender, InfoBarClosedEventArgs args) => VM.ClearError();

    private void SearchBox_TextChanging(TextBox sender, TextBoxTextChangingEventArgs args)
    {
        // TextChanged is queued: it can reset selection after a rapid Down/Enter.
        if (!_initializing && sender.Text != VM.SearchText) OnSearchTextChanged(sender.Text);
    }

    private void ResultsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        VM.SelectedEntry = ResultsList.SelectedItem as EntryItem;
        OnSelectionChanged(VM.SelectedEntry);
    }

    private void ViewSelector_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
    {
        if (_syncingView)
        {
            return;
        }

        ShellView view = sender.SelectedItem == CodesTab
            ? ShellView.Codes
            : sender.SelectedItem == EditorTab ? ShellView.Editor : ShellView.Details;
        SelectView(view);
    }

    private void EditorActionBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_initializing || EditorActionBox.SelectedIndex < 0)
        {
            return;
        }

        VM.EditorActionIndex = EditorActionBox.SelectedIndex;
    }

    private void EditorNameBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_initializing)
        {
            VM.EditorNameText = EditorNameBox.Text;
        }
    }

    private void EditorSubkeysBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_initializing)
        {
            VM.EditorSubkeysText = EditorSubkeysBox.Text;
        }
    }

    private void EditorNewNameBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_initializing)
        {
            VM.EditorNewNameText = EditorNewNameBox.Text;
        }
    }

    private void CopyCode_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement element && element.DataContext is CodeItem item)
        {
            _ = CopyCodeAsync(new EntryItem(item.Info));
        }
    }

    private void ApplyHotkey_Click(object sender, RoutedEventArgs e) => RegisterHotkeyFromUi(reportSuccess: true);

    private void LaunchAtSignIn_Toggled(object sender, RoutedEventArgs e)
    {
        if (!_initializing && sender is ToggleSwitch toggle)
        {
            _ = SetLaunchAtSignInAsync(toggle.IsOn);
        }
    }

    private void ClearClipboard_Toggled(object sender, RoutedEventArgs e)
    {
        if (!_initializing && sender is ToggleSwitch toggle)
        {
            VM.ClearClipboardOnLock = toggle.IsOn;
        }
    }

    // ---- keyboard --------------------------------------------------------

    private static bool KeyDown(VirtualKey key) =>
        (InputKeyboardSource.GetKeyStateForCurrentThread(key) & CoreVirtualKeyStates.Down) != 0;

    private void Palette_PreviewKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (!VM.IsUnlocked || e.Handled || KeyDown(VirtualKey.Menu) || KeyDown(VirtualKey.Shift) ||
            KeyDown(VirtualKey.LeftWindows) || KeyDown(VirtualKey.RightWindows)) return;
        bool ctrl = KeyDown(VirtualKey.Control);
        if (_showingTools)
        {
            // Let editors, drop-downs and multiline inputs keep their native key handling.
            if (e.Key == VirtualKey.Escape && !ctrl && !EditorActionBox.IsDropDownOpen)
            {
                ShowSearch();
                e.Handled = true;
            }
            return;
        }

        // Never steal Enter from a focused footer button or from settings.
        DependencyObject? origin = e.OriginalSource as DependencyObject;
        while (origin is not null && origin != SearchPane)
            origin = VisualTreeHelper.GetParent(origin);
        if (origin is null) return;
        switch (e.Key)
        {
            case VirtualKey.Up or VirtualKey.Down when !ctrl:
                if (_resultsQuery == SearchBox.Text && VM.Results.Count > 0)
                {
                    ResultsList.SelectedIndex = Math.Clamp(ResultsList.SelectedIndex +
                        (e.Key == VirtualKey.Down ? 1 : -1), 0, VM.Results.Count - 1);
                    ResultsList.ScrollIntoView(ResultsList.SelectedItem);
                }
                break;
            case VirtualKey.Enter:
                if (HasCurrentSelection && !e.KeyStatus.WasKeyDown && (!ctrl || CodeAction.IsEnabled))
                    _ = ctrl ? CopySelectedCodeAsync() : CopySelectedAsync();
                break;
            case VirtualKey.O when ctrl:
                if (HasCurrentSelection) SelectView(ShellView.Details);
                break;
            case VirtualKey.Escape when !ctrl:
                HideToTray();
                break;
            default:
                return;
        }
        e.Handled = true;
    }

    private void FocusSearch_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        ShowSearch();
        args.Handled = true;
    }

    private void ToggleLock_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (VM.IsUnlocked)
        {
            _ = LockAsync();
        }
        else if (VM.IsLocked)
        {
            _ = UnlockAsync(withHello: false);
        }

        args.Handled = true;
    }

    private void Unlock_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (VM.IsLocked)
        {
            _ = UnlockAsync(withHello: false);
        }

        args.Handled = true;
    }

    private void Refresh_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        _ = RefreshAsync();
        args.Handled = true;
    }

    private void ShowDetails_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        SelectView(ShellView.Details);
        args.Handled = true;
    }

    private void ShowCodes_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        SelectView(ShellView.Codes);
        args.Handled = true;
    }

    private void ShowEditor_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        SelectView(ShellView.Editor);
        args.Handled = true;
    }

    // ---- hotkey / startup ------------------------------------------------

    private void OnHotkeyPressed(int hotkeyId)
    {
        if (hotkeyId != HotkeyRegistration.HotkeyId)
        {
            return;
        }

        DispatcherQueue.TryEnqueue(ShowShellSafe);
    }

    private static HotkeyChoice LoadHotkeySetting()
    {
        try
        {
            if (ApplicationData.Current.LocalSettings.Values[HotkeySettingsKey] is string serialized &&
                HotkeyChoice.TryParse(serialized, out HotkeyChoice choice))
            {
                return choice;
            }
        }
        catch (Exception)
        {
            // Fall through to the default combination.
        }

        return new HotkeyChoice(Control: true, Alt: true, Shift: false, Win: false, VirtualKey: 'W');
    }

    private uint SelectedKeyValue()
    {
        int index = HotkeyKeyBox.SelectedIndex;
        return index >= 0 && index < HotkeyChoice.KnownKeys.Count
            ? HotkeyChoice.KnownKeys[index].Vk
            : (uint)'W';
    }

    private static int IndexOfKey(uint virtualKey)
    {
        for (int i = 0; i < HotkeyChoice.KnownKeys.Count; i++)
        {
            if (HotkeyChoice.KnownKeys[i].Vk == virtualKey)
            {
                return i;
            }
        }

        return -1;
    }

    private void RegisterHotkeyFromUi(bool reportSuccess)
    {
        var choice = new HotkeyChoice(
            HotkeyCtrl.IsChecked == true,
            HotkeyAlt.IsChecked == true,
            HotkeyShift.IsChecked == true,
            HotkeyWin.IsChecked == true,
            SelectedKeyValue());

        try
        {
            ApplicationData.Current.LocalSettings.Values[HotkeySettingsKey] = choice.Serialize();
        }
        catch (Exception)
        {
            // Settings persistence is best effort; the registration below is not.
        }

        if (_hotkeys is null)
        {
            return;
        }

        if (_hotkeys.TryRegister(choice, out int win32Error))
        {
            VM.HotkeyDisplayText = "Hotkey: " + choice.DisplayText;
            VM.HotkeyErrorText = null;
            if (reportSuccess)
            {
                VM.StatusText = "Hotkey registered: " + choice.DisplayText;
            }
        }
        else
        {
            // Visible failure: banner + settings flyout text, never silent.
            VM.HotkeyDisplayText = "Hotkey: " + choice.DisplayText + " (not registered)";
            VM.HotkeyErrorText = $"RegisterHotKey failed for {choice.DisplayText} (Win32 error {win32Error}). The combination may already be in use by another application.";
            VM.ShowError("Global hotkey", VM.HotkeyErrorText, warning: true);
        }
    }

    private async Task LoadStartupStateAsync()
    {
        try
        {
            StartupTask task = await StartupTask.GetAsync(StartupTaskId);
            VM.LaunchAtSignIn = task.State == StartupTaskState.Enabled;
            LaunchAtSignInSwitch.IsOn = VM.LaunchAtSignIn;
        }
        catch (Exception ex)
        {
            VM.ShowError("Launch at sign-in", ex.Message, warning: true);
        }
    }

    private async Task SetLaunchAtSignInAsync(bool enable)
    {
        try
        {
            StartupTask task = await StartupTask.GetAsync(StartupTaskId);
            if (enable)
            {
                StartupTaskState state = await task.RequestEnableAsync();
                VM.LaunchAtSignIn = state == StartupTaskState.Enabled;
                if (!VM.LaunchAtSignIn)
                {
                    VM.ShowError("Launch at sign-in", "Windows did not enable launch at sign-in (state: " + state + ").", warning: true);
                }
            }
            else
            {
                task.Disable();
                VM.LaunchAtSignIn = false;
            }

            LaunchAtSignInSwitch.IsOn = VM.LaunchAtSignIn;
        }
        catch (Exception ex)
        {
            VM.LaunchAtSignIn = false;
            LaunchAtSignInSwitch.IsOn = false;
            VM.ShowError("Launch at sign-in", ex.Message, warning: true);
        }
    }

    // ---- misc ------------------------------------------------------------

    private static byte[]? EncodeNeedle(string searchText)
    {
        if (string.IsNullOrEmpty(searchText))
        {
            return Array.Empty<byte>();
        }

        // The needle is a case-insensitive substring match on raw name bytes
        // (upstream list semantics). Names are bounded to 255 bytes, so a
        // longer needle can never match; null means "impossible needle".
        byte[] bytes = NameCodec.Utf8Bytes(searchText);
        return bytes.Length <= NameCodec.MaxNameBytes ? bytes : null;
    }
}
