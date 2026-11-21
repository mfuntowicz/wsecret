using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;

namespace WSecret;

// ---------------------------------------------------------------------------
// View models for the Quick Access shell. SECURITY CONTRACT: this file (and
// everything reachable from it) holds METADATA ONLY — raw name bytes, slots,
// counts, countdowns, lifecycle state. Secret values, passphrases, TOTP seeds
// and TOTP digits never enter the CLR; they are handled exclusively by the
// broker process (masked prompts, secure clipboard).
//
// Visibility: XAML-bound types and members are public because the XAML
// compiler resolves them without the local assembly context; purely
// code-behind state stays internal.
// ---------------------------------------------------------------------------

/// <summary>Minimal INotifyPropertyChanged base (no MVVM framework dependency).</summary>
public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

internal sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    internal RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

    public void Execute(object? parameter) => _execute(parameter);

    internal void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

internal sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<object?, Task> _execute;
    private readonly Func<object?, bool>? _canExecute;
    private bool _running;

    internal AsyncRelayCommand(Func<object?, Task> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => !_running && (_canExecute?.Invoke(parameter) ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter))
        {
            return;
        }

        _running = true;
        RaiseCanExecuteChanged();
        try
        {
            await _execute(parameter);
        }
        catch (Exception ex)
        {
            // Command failures are surfaced through the shell status/InfoBar
            // by the action implementations; swallow only if none did.
            System.Diagnostics.Debug.WriteLine("Command failed: " + ex.GetType().Name);
        }
        finally
        {
            _running = false;
            RaiseCanExecuteChanged();
        }
    }

    internal void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>Right-pane view selection.</summary>
public enum ShellView
{
    Details = 0,
    Codes = 1,
    Editor = 2,
}

/// <summary>Editor operations (metadata only; values are entered broker-side).</summary>
public enum WriteAction
{
    /// <summary>Upstream `new`: generate a random secret and store it.</summary>
    NewRandom = 0,

    /// <summary>Deterministic secret (upstream `pass` components) stored as a record.</summary>
    NewDeterministic = 1,

    /// <summary>Upstream `set`: create, value typed in the broker's masked prompt.</summary>
    SetTypedValue = 2,

    /// <summary>Upstream `update` with a new value typed in the broker's prompt.</summary>
    ReplaceTypedValue = 3,

    /// <summary>Upstream `update KEY NEWKEY`: rename only, value preserved.</summary>
    RenameOnly = 4,

    /// <summary>Upstream `renew`: replace with a freshly generated secret.</summary>
    Renew = 5,

    /// <summary>Rename into the DELETED: namespace (slot reuse marker).</summary>
    Tombstone = 6,
}

/// <summary>
/// One list row: exact raw name bytes plus the lossy presentation projection
/// (<see cref="Title"/>, <see cref="Breadcrumb"/>, <see cref="CreateIcon"/>). Identity
/// is always the raw name plus the slot; rows are never merged or deduplicated.
/// <see cref="DisplayName"/> keeps the full lossy name so the exact path stays
/// reachable through the row's tooltip and accessible name.
/// </summary>
public sealed class EntryItem
{
    internal EntryItem(EntryInfo info)
    {
        Info = info;
        var presentation = EntryPresentation.Present(info.RawName, info.IsCodeName);
        Title = presentation.Title;
        Breadcrumb = presentation.Breadcrumb;
        _iconPath = presentation.IconPath;
        _brandMark = presentation.BrandMark;
    }

    internal EntryInfo Info { get; }
    internal ulong Slot => Info.Slot;
    internal byte[] RawName => Info.RawName;
    internal bool IsCode => Info.IsCodeName;

    public string DisplayName => Info.DisplayName;
    public string KindLabel => IsCode ? "Code" : "Secret";

    /// <summary>
    /// Row headline: the account (the component above a credential-field leaf)
    /// or, for other names, the leaf itself.
    /// </summary>
    public string Title { get; }

    /// <summary>
    /// Container path above <see cref="Title"/>. Synthesized and named Default roots
    /// remain distinct; empty segments are explicit.
    /// </summary>
    public string Breadcrumb { get; }

    private readonly string _iconPath;
    private readonly bool _brandMark;

    // A WinUI Geometry has one visual owner. Share the path literal, not the
    // Geometry: assigning the same instance to two PathIcons fails with E_INVALIDARG.
    public Geometry CreateIcon() => (Geometry)XamlBindingHelper.ConvertValue(typeof(Geometry), _iconPath);
    public Style? IconStyle => _brandMark ? (Style)Application.Current.Resources["BrandResultIcon"] : null;

    public override string ToString() => DisplayName;
}

/// <summary>
/// Row presentation for <see cref="EntryItem"/> (docs/quick-access.md §4.1).
/// PRESENTATION ONLY: everything here is a lossy projection of the raw name —
/// identity remains the exact raw bytes plus slot, nothing is grouped, merged or
/// deduplicated, and the full path stays available through the raw display name.
/// Only a terminal "password" field promotes the account name to the headline;
/// other fields (key, username, token, etc.) stay visibly distinguishable.
/// </summary>
internal static class EntryPresentation
{
    /// <summary>Breadcrumb joiner (U+203A SINGLE RIGHT-POINTING ANGLE QUOTATION MARK).</summary>
    internal const string CrumbSeparator = " \u203A ";

    /// <summary>The synthesized ungrouped root ("Default (ungrouped)" in the contract).</summary>
    internal const string RootCrumb = "Default";

    /// <summary>A literal first name segment "Default" — kept distinct from the synthesized root.</summary>
    internal const string NamedDefaultCrumb = "Default (named)";

    /// <summary>Empty path-segment marker (U+2300 EMPTY SET SIGN).</summary>
    private const string EmptySegmentMarker = "⌀";

    private static readonly HashSet<string> TerminalTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "terminal", "console", "shell", "cli", "cmd", "powershell", "pwsh", "wsl", "ssh",
        "github-cli", "github_cli", "gh-cli", "git-bash", "windows-terminal", "iterm", "iterm2",
    };

    private static readonly HashSet<string> GitHubTokens = new(StringComparer.OrdinalIgnoreCase) { "github", "github.com" };
    private static readonly HashSet<string> GitLabTokens = new(StringComparer.OrdinalIgnoreCase) { "gitlab", "gitlab.com" };

    private enum MarkKind
    {
        None,
        Key,
        Code,
        Terminal,
        GitHub,
        GitLab,
    }

    internal static (string Title, string Breadcrumb, string IconPath, bool BrandMark) Present(byte[] rawName, bool isCode)
    {
        ReadOnlySpan<byte> name = rawName;
        var segments = new List<string>();
        foreach (Range range in name.Split((byte)'/'))
            segments.Add(EscapeSegment(name[range]));

        int last = segments.Count - 1;
        int titleIndex = last > 0 && segments[last] == "password" ? last - 1 : last;
        string title = segments[titleIndex];
        MarkKind kind = MatchToken(title);
        if (kind == MarkKind.None)
        {
            foreach (string segment in segments)
                if ((kind = MatchToken(segment)) != MarkKind.None) break;
        }

        if (kind == MarkKind.None) kind = isCode ? MarkKind.Code : MarkKind.Key;

        segments.RemoveRange(titleIndex, segments.Count - titleIndex);
        if (last < 2) segments.Insert(0, RootCrumb);
        else if (segments.Count > 0 && segments[0] == "Default") segments[0] = NamedDefaultCrumb;
        return (title, string.Join(CrumbSeparator, segments), Mark(kind), kind == MarkKind.GitLab);
    }

    private static MarkKind MatchToken(string token)
    {
        if (TerminalTokens.Contains(token))
        {
            return MarkKind.Terminal;
        }

        if (GitLabTokens.Contains(token))
        {
            return MarkKind.GitLab;
        }

        if (GitHubTokens.Contains(token))
        {
            return MarkKind.GitHub;
        }

        return MarkKind.None;
    }

    /// <summary>
    /// Injective per-segment escaping (docs/quick-access.md §4.1): printable
    /// ASCII 0x21..0x7E renders literally except '\' (renders "\\"); every other
    /// byte renders as "\xNN" (lowercase hex); an empty segment renders "⌀".
    /// Literal marker text therefore cannot collide with the markers.
    /// </summary>
    private static string EscapeSegment(ReadOnlySpan<byte> segment)
    {
        if (segment.Length == 0)
        {
            return EmptySegmentMarker;
        }

        if (segment.IndexOfAnyExceptInRange((byte)0x21, (byte)0x7e) < 0 && !segment.Contains((byte)'\\'))
            return Encoding.ASCII.GetString(segment);
        var builder = new StringBuilder(segment.Length);
        foreach (byte b in segment)
        {
            if (b == (byte)'\\')
            {
                builder.Append("\\\\");
            }
            else if (b is >= 0x21 and <= 0x7E)
            {
                builder.Append((char)b);
            }
            else
            {
                builder.Append("\\x").Append(b.ToString("x2"));
            }
        }

        return builder.ToString();
    }

    private static string Mark(MarkKind kind) => kind switch
    {
        MarkKind.Terminal => TerminalMarkData,
        MarkKind.GitHub => GitHubMarkData,
        MarkKind.GitLab => GitLabMarkData,
        MarkKind.Code => CodeMarkData,
        _ => KeyMarkData,
    };

    // ---- fixed mark path data (XAML geometry mini-language) --------------

    private const string GitHubMarkData =
        "M 12 0.297 C 5.37 0.297 0 5.67 0 12.297 C 0 17.6 3.438 22.097 8.205 23.682 C 8.805 23.795 9.025 23.424 9.025 " +
        "23.105 C 9.025 22.82 9.015 22.065 9.01 21.065 C 5.672 21.789 4.968 19.455 4.968 19.455 C 4.422 18.07 3.633 " +
        "17.7 3.633 17.7 C 2.546 16.956 3.717 16.971 3.717 16.971 C 4.922 17.055 5.555 18.207 5.555 18.207 C 6.625 " +
        "20.042 8.364 19.512 9.05 19.205 C 9.158 18.429 9.467 17.9 9.81 17.6 C 7.145 17.3 4.344 16.268 4.344 11.67 C " +
        "4.344 10.36 4.809 9.29 5.579 8.45 C 5.444 8.147 5.039 6.927 5.684 5.274 C 5.684 5.274 6.689 4.952 8.984 6.504 " +
        "C 9.944 6.237 10.964 6.105 11.984 6.099 C 13.004 6.105 14.024 6.237 14.984 6.504 C 17.264 4.952 18.269 5.274 " +
        "18.269 5.274 C 18.914 6.927 18.509 8.147 18.389 8.45 C 19.154 9.29 19.619 10.36 19.619 11.67 C 19.619 16.28 " +
        "16.814 17.295 14.144 17.59 C 14.564 17.95 14.954 18.686 14.954 19.81 C 14.954 21.416 14.939 22.706 14.939 " +
        "23.096 C 14.939 23.411 15.149 23.786 15.764 23.666 C 20.565 22.092 24 17.592 24 12.297 C 24 5.67 18.627 0.297 " +
        "12 0.297 Z";

    private const string GitLabMarkData =
        "M 23.955 13.587 C 23.508 12.209 23.06 10.83 22.613 9.452 C 21.725 6.722 20.837 3.993 19.949 1.263 C 19.66 " +
        "1.263 19.371 1.263 19.082 1.263 C 18.194 3.992 17.306 6.721 16.418 9.45 C 13.473 9.45 10.527 9.45 7.582 9.45 " +
        "C 6.694 6.721 5.807 3.992 4.919 1.263 C 4.629 1.263 4.34 1.263 4.05 1.263 C 3.162 3.992 2.274 6.721 1.386 " +
        "9.45 C 0.939 10.829 0.491 12.208 0.044 13.587 C 0.154 13.928 0.265 14.269 0.375 14.61 C 4.25 17.425 8.125 " +
        "20.239 12 23.054 C 15.875 20.24 19.75 17.425 23.625 14.611 C 23.735 14.27 23.845 13.928 23.955 13.587 Z";

    private const string TerminalMarkData =
        "M 4 3.4 C 9.333 3.4 14.667 3.4 20 3.4 C 21.436 3.4 22.6 4.564 22.6 6 C 22.6 10 22.6 14 22.6 18 C 22.6 19.436 " +
        "21.436 20.6 20 20.6 C 14.667 20.6 9.333 20.6 4 20.6 C 2.564 20.6 1.4 19.436 1.4 18 C 1.4 14 1.4 10 1.4 6 C " +
        "1.4 4.564 2.564 3.4 4 3.4 Z M 4.9 5.6 C 4.182 5.6 3.6 6.182 3.6 6.9 C 3.6 10.3 3.6 13.7 3.6 17.1 C 3.6 17.818 " +
        "4.182 18.4 4.9 18.4 C 9.633 18.4 14.367 18.4 19.1 18.4 C 19.818 18.4 20.4 17.818 20.4 17.1 C 20.4 13.7 20.4 " +
        "10.3 20.4 6.9 C 20.4 6.182 19.818 5.6 19.1 5.6 C 14.367 5.6 9.633 5.6 4.9 5.6 Z M 6.284 9.235 C 7.359 10.157 " +
        "8.435 11.078 9.51 12 C 8.435 12.922 7.359 13.843 6.284 14.765 C 6.761 15.322 7.239 15.878 7.716 16.435 C " +
        "9.441 14.957 11.165 13.478 12.89 12 C 11.165 10.522 9.441 9.043 7.716 7.565 C 7.239 8.122 6.761 8.678 6.284 " +
        "9.235 Z M 13.2 14.5 C 15.067 14.5 16.933 14.5 18.8 14.5 C 18.8 15.233 18.8 15.967 18.8 16.7 C 16.933 16.7 " +
        "15.067 16.7 13.2 16.7 C 13.2 15.967 13.2 15.233 13.2 14.5 Z";

    private const string KeyMarkData =
        "M 11.8 12 C 11.8 14.872 9.472 17.2 6.6 17.2 C 3.728 17.2 1.4 14.872 1.4 12 C 1.4 9.128 3.728 6.8 6.6 6.8 C " +
        "9.472 6.8 11.8 9.128 11.8 12 Z M 8.9 12 C 8.9 10.73 7.87 9.7 6.6 9.7 C 5.33 9.7 4.3 10.73 4.3 12 C 4.3 13.27 " +
        "5.33 14.3 6.6 14.3 C 7.87 14.3 8.9 13.27 8.9 12 Z M 11 10.9 C 14.667 10.9 18.333 10.9 22 10.9 C 22 11.633 22 " +
        "12.367 22 13.1 C 18.333 13.1 14.667 13.1 11 13.1 C 11 12.367 11 11.633 11 10.9 Z M 15.8 13.1 C 16.533 13.1 " +
        "17.267 13.1 18 13.1 C 18 14.233 18 15.367 18 16.5 C 17.267 16.5 16.533 16.5 15.8 16.5 C 15.8 15.367 15.8 " +
        "14.233 15.8 13.1 Z M 19.2 13.1 C 19.933 13.1 20.667 13.1 21.4 13.1 C 21.4 13.967 21.4 14.833 21.4 15.7 C " +
        "20.667 15.7 19.933 15.7 19.2 15.7 C 19.2 14.833 19.2 13.967 19.2 13.1 Z";

    private const string CodeMarkData =
        "M 8.029 5.416 C 5.796 7.61 3.564 9.805 1.331 12 C 3.564 14.195 5.796 16.39 8.029 18.584 C 8.543 18.061 9.057 " +
        "17.539 9.571 17.016 C 7.87 15.344 6.17 13.672 4.469 12 C 6.17 10.328 7.87 8.656 9.571 6.984 C 9.057 6.461 " +
        "8.543 5.939 8.029 5.416 Z M 11.665 18.475 C 12.732 14.342 13.798 10.208 14.865 6.075 C 14.155 5.892 13.445 " +
        "5.708 12.735 5.525 C 11.668 9.658 10.602 13.792 9.535 17.925 C 10.245 18.108 10.955 18.292 11.665 18.475 Z M " +
        "14.829 6.984 C 16.53 8.656 18.23 10.328 19.931 12 C 18.23 13.672 16.53 15.344 14.829 17.016 C 15.343 17.539 " +
        "15.857 18.061 16.371 18.584 C 18.604 16.39 20.836 14.195 23.069 12 C 20.836 9.805 18.604 7.61 16.371 5.416 C " +
        "15.857 5.939 15.343 6.461 14.829 6.984 Z";
}

/// <summary>
/// One Codes-view row. Renders the countdown only — the TOTP digits are never
/// fetched; copying goes through the broker's secure clipboard (opcode 0x0023).
/// </summary>
public sealed class CodeItem : ObservableObject
{
    private int _secondsLeft;

    internal CodeItem(EntryInfo info, uint initialRemaining)
    {
        Info = info;
        PeriodSeconds = Math.Max(1, (int)initialRemaining);
        _secondsLeft = (int)initialRemaining;
    }

    internal EntryInfo Info { get; }

    public string DisplayName => Info.DisplayName;

    public int PeriodSeconds { get; }

    public int SecondsLeft
    {
        get => _secondsLeft;
        private set
        {
            if (SetProperty(ref _secondsLeft, value))
            {
                OnPropertyChanged(nameof(CountdownText));
            }
        }
    }

    public string CountdownText => SecondsLeft > 0 ? SecondsLeft + " s" : "—";

    internal void RefreshRemaining(uint remaining) => SecondsLeft = (int)remaining;

    internal void Tick()
    {
        if (SecondsLeft > 0)
        {
            SecondsLeft--;
        }
    }

    public override string ToString() => DisplayName;
}

/// <summary>Actions the view model delegates to the shell controller.</summary>
public interface IShellActions
{
    Task UnlockAsync(bool withHello);
    Task LockAsync();
    Task RefreshAsync();
    Task CopySelectedAsync();
    Task CopyCodeAsync(EntryItem? entry);
    Task EditSelectedAsync();
    Task RenewSelectedAsync();
    Task TombstoneSelectedAsync();
    Task ApplyEditorAsync();
    Task EnrollHelloAsync();
    Task ForgetHelloAsync();
    Task RetryBrokerAsync();
    void OnSearchTextChanged(string text);
    void OnSelectionChanged(EntryItem? entry);
    void SetActiveView(ShellView view);
}

/// <summary>Observable shell state. Metadata only; never secret bytes.</summary>
public sealed class ShellViewModel : ObservableObject
{
    private readonly IShellActions _actions;

    // Lifecycle / connection.
    private BrokerLifecycle _state = BrokerLifecycle.Locked;
    private HelloState _helloState = HelloState.UnsupportedFailDisabled;
    private BrokerCaps _caps = BrokerCaps.None;
    private bool _brokerConnected;
    private string _statusText = "Starting…";

    // Search / results.
    private string _searchText = string.Empty;
    private EntryItem? _selectedEntry;
    private string _entryCountText = "0 entries";

    // Details.
    private string _selectedDisplayName = string.Empty;
    private string _selectedMetaText = "Select an entry to see its details.";

    // Views.
    private ShellView _activeView = ShellView.Details;

    // Editor.
    private string _editorNameText = string.Empty;
    private string _editorNewNameText = string.Empty;
    private string _editorSubkeysText = string.Empty;
    private WriteAction _editorAction = WriteAction.NewRandom;
    private string _editorResultText = string.Empty;

    // Settings / status.
    private string _hotkeyDisplayText = string.Empty;
    private string? _hotkeyErrorText;
    private bool _launchAtSignIn;
    private bool _clearClipboardOnLock = true;
    private bool _errorOpen;
    private string _errorTitle = string.Empty;
    private string _errorText = string.Empty;

    public ShellViewModel(IShellActions actions)
    {
        _actions = actions;
        UnlockCommand = new AsyncRelayCommand(_ => _actions.UnlockAsync(withHello: false));
        UnlockWithHelloCommand = new AsyncRelayCommand(_ => _actions.UnlockAsync(withHello: true), _ => HelloAvailable);
        LockCommand = new AsyncRelayCommand(_ => _actions.LockAsync(), _ => IsUnlocked);
        RefreshCommand = new AsyncRelayCommand(_ => _actions.RefreshAsync());
        CopyCommand = new AsyncRelayCommand(_ => _actions.CopySelectedAsync(), _ => SelectedEntry is not null && IsUnlocked);
        CopyCodeCommand = new AsyncRelayCommand(p => _actions.CopyCodeAsync(p as EntryItem ?? SelectedEntry), _ => IsUnlocked);
        EditCommand = new AsyncRelayCommand(_ => _actions.EditSelectedAsync(), _ => SelectedEntry is not null && IsUnlocked);
        RenewCommand = new AsyncRelayCommand(_ => _actions.RenewSelectedAsync(), _ => SelectedEntry is not null && IsUnlocked);
        TombstoneCommand = new AsyncRelayCommand(_ => _actions.TombstoneSelectedAsync(), _ => SelectedEntry is not null && IsUnlocked);
        ApplyEditorCommand = new AsyncRelayCommand(_ => _actions.ApplyEditorAsync(), _ => IsUnlocked && EditorWritesEnabled);
        EnrollHelloCommand = new AsyncRelayCommand(_ => _actions.EnrollHelloAsync(), _ => HelloAvailable && IsUnlocked);
        ForgetHelloCommand = new AsyncRelayCommand(_ => _actions.ForgetHelloAsync(), _ => HelloAvailable);
        RetryBrokerCommand = new AsyncRelayCommand(_ => _actions.RetryBrokerAsync());
    }

    // ---- commands --------------------------------------------------------

    public ICommand UnlockCommand { get; }
    public ICommand UnlockWithHelloCommand { get; }
    public ICommand LockCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand CopyCommand { get; }
    public ICommand CopyCodeCommand { get; }
    public ICommand EditCommand { get; }
    public ICommand RenewCommand { get; }
    public ICommand TombstoneCommand { get; }
    public ICommand ApplyEditorCommand { get; }
    public ICommand EnrollHelloCommand { get; }
    public ICommand ForgetHelloCommand { get; }
    public ICommand RetryBrokerCommand { get; }

    // ---- lifecycle / connection -----------------------------------------

    internal BrokerLifecycle State
    {
        get => _state;
        set
        {
            if (SetProperty(ref _state, value))
            {
                OnPropertyChanged(nameof(IsUnlocked));
                OnPropertyChanged(nameof(IsLocked));
                OnPropertyChanged(nameof(IsBusy));
                OnPropertyChanged(nameof(StateLabel));
                OnPropertyChanged(nameof(WindowTitle));
                OnPropertyChanged(nameof(LockButtonLabel));
                RaiseCommandStates();
            }
        }
    }

    public bool IsUnlocked => State == BrokerLifecycle.Unlocked;
    public bool IsLocked => State == BrokerLifecycle.Locked;
    public bool IsBusy => State is BrokerLifecycle.Unlocking or BrokerLifecycle.Locking;

    public string StateLabel => State switch
    {
        BrokerLifecycle.Locked => "Locked",
        BrokerLifecycle.Unlocking => "Unlocking…",
        BrokerLifecycle.Unlocked => "Unlocked",
        BrokerLifecycle.Locking => "Locking…",
        _ => "Unknown",
    };

    public string LockButtonLabel => IsUnlocked ? "Lock" : "Unlock";

    public string WindowTitle => IsUnlocked
        ? "WSecret — Quick Access (Unlocked)"
        : "WSecret — Quick Access (Locked)";

    public bool BrokerConnected
    {
        get => _brokerConnected;
        set
        {
            if (SetProperty(ref _brokerConnected, value))
            {
                OnPropertyChanged(nameof(EditorWritesEnabled));
                RaiseCommandStates();
            }
        }
    }

    internal BrokerCaps Caps
    {
        get => _caps;
        set
        {
            if (SetProperty(ref _caps, value))
            {
                OnPropertyChanged(nameof(HelloAvailable));
                RaiseCommandStates();
            }
        }
    }

    internal HelloState Hello
    {
        get => _helloState;
        set
        {
            if (SetProperty(ref _helloState, value))
            {
                OnPropertyChanged(nameof(HelloStateText));
                OnPropertyChanged(nameof(HelloAvailable));
                RaiseCommandStates();
            }
        }
    }

    public bool HelloAvailable => (Caps & BrokerCaps.Hello) != 0;

    public string HelloStateText => !HelloAvailable
        ? "Windows Hello is unavailable (fail-disabled) on this device."
        : Hello switch
        {
            HelloState.AvailableNotEnrolled => "Windows Hello is available but not enrolled for this store.",
            HelloState.Enrolled => "Windows Hello is enrolled for this store.",
            _ => "Windows Hello is unavailable (fail-disabled).",
        };

    /// <summary>Applies authoritative state from the broker.</summary>
    internal void ApplyBrokerState(BrokerLifecycle lifecycle, HelloState hello, BrokerCaps? caps = null)
    {
        if (caps is not null)
        {
            Caps = caps.Value;
        }

        Hello = hello;
        State = lifecycle;
    }

    // ---- status / errors -------------------------------------------------

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public bool ErrorOpen
    {
        get => _errorOpen;
        private set => SetProperty(ref _errorOpen, value);
    }

    public string ErrorTitle
    {
        get => _errorTitle;
        private set => SetProperty(ref _errorTitle, value);
    }

    public string ErrorText
    {
        get => _errorText;
        private set => SetProperty(ref _errorText, value);
    }

    public bool ErrorIsWarning { get; private set; }

    public void ShowError(string title, string text, bool warning = false)
    {
        ErrorIsWarning = warning;
        OnPropertyChanged(nameof(ErrorIsWarning));
        ErrorTitle = title;
        ErrorText = text;
        ErrorOpen = true;
    }

    public void ClearError() => ErrorOpen = false;

    // ---- search / results ------------------------------------------------

    public string SearchText
    {
        get => _searchText;
        set => SetProperty(ref _searchText, value);
    }

    public ObservableCollection<EntryItem> Results { get; } = new();

    public EntryItem? SelectedEntry
    {
        get => _selectedEntry;
        set
        {
            if (SetProperty(ref _selectedEntry, value))
            {
                RaiseCommandStates();
            }
        }
    }

    public string EntryCountText
    {
        get => _entryCountText;
        set => SetProperty(ref _entryCountText, value);
    }

    // ---- details ---------------------------------------------------------

    public string SelectedDisplayName
    {
        get => _selectedDisplayName;
        set => SetProperty(ref _selectedDisplayName, value);
    }

    public string SelectedMetaText
    {
        get => _selectedMetaText;
        set => SetProperty(ref _selectedMetaText, value);
    }

    // ---- codes -----------------------------------------------------------

    public ObservableCollection<CodeItem> Codes { get; } = new();

    // ---- views -----------------------------------------------------------

    public ShellView ActiveView
    {
        get => _activeView;
        private set
        {
            if (SetProperty(ref _activeView, value))
            {
                OnPropertyChanged(nameof(IsDetailsView));
                OnPropertyChanged(nameof(IsCodesView));
                OnPropertyChanged(nameof(IsEditorView));
            }
        }
    }

    public bool IsDetailsView => ActiveView == ShellView.Details;
    public bool IsCodesView => ActiveView == ShellView.Codes;
    public bool IsEditorView => ActiveView == ShellView.Editor;

    public void SetActiveView(ShellView view) => ActiveView = view;

    // ---- editor ----------------------------------------------------------

    /// <summary>Editor operation labels for the ComboBox (order matches WriteAction).</summary>
    public IReadOnlyList<string> EditorActionNames { get; } = new[]
    {
        "New — generate a random secret (upstream new)",
        "New — deterministic secret from components (upstream pass)",
        "Set — store a typed value (upstream set)",
        "Update — replace with a typed value (upstream update)",
        "Rename — keep the value (upstream update KEY NEWKEY)",
        "Renew — replace with a fresh generated secret (upstream renew)",
        "Tombstone — rename into DELETED: (slot reuse marker)",
    };

    public WriteAction EditorAction
    {
        get => _editorAction;
        set
        {
            if (SetProperty(ref _editorAction, value))
            {
                OnPropertyChanged(nameof(EditorWritesEnabled));
                RaiseCommandStates();
            }
        }
    }

    public int EditorActionIndex
    {
        get => (int)_editorAction;
        set => EditorAction = (WriteAction)Math.Clamp(value, 0, 6);
    }

    public string EditorNameText
    {
        get => _editorNameText;
        set
        {
            if (SetProperty(ref _editorNameText, value))
            {
                OnPropertyChanged(nameof(EditorWritesEnabled));
                RaiseCommandStates();
            }
        }
    }

    public string EditorNewNameText
    {
        get => _editorNewNameText;
        set => SetProperty(ref _editorNewNameText, value);
    }

    public string EditorSubkeysText
    {
        get => _editorSubkeysText;
        set => SetProperty(ref _editorSubkeysText, value);
    }

    public string EditorResultText
    {
        get => _editorResultText;
        set => SetProperty(ref _editorResultText, value);
    }

    /// <summary>True when the current editor action can be submitted.</summary>
    public bool EditorWritesEnabled => BrokerConnected && IsUnlocked && EditorNameText.Length > 0;

    // ---- settings --------------------------------------------------------

    public string HotkeyDisplayText
    {
        get => _hotkeyDisplayText;
        set => SetProperty(ref _hotkeyDisplayText, value);
    }

    public string? HotkeyErrorText
    {
        get => _hotkeyErrorText;
        set
        {
            if (SetProperty(ref _hotkeyErrorText, value))
            {
                OnPropertyChanged(nameof(HasHotkeyError));
            }
        }
    }

    public bool HasHotkeyError => _hotkeyErrorText is not null;

    public bool LaunchAtSignIn
    {
        get => _launchAtSignIn;
        set => SetProperty(ref _launchAtSignIn, value);
    }

    public bool ClearClipboardOnLock
    {
        get => _clearClipboardOnLock;
        set => SetProperty(ref _clearClipboardOnLock, value);
    }

    // ---- helpers ---------------------------------------------------------

    public void ResetForLock()
    {
        // Metadata wipe on lock: no entry names, countdowns or details survive
        // the locked state in the CLR.
        Results.Clear();
        Codes.Clear();
        SelectedEntry = null;
        SelectedDisplayName = string.Empty;
        SelectedMetaText = "Select an entry to see its details.";
        EditorResultText = string.Empty;
    }

    private void RaiseCommandStates()
    {
        foreach (ICommand command in new ICommand[]
        {
            UnlockCommand, UnlockWithHelloCommand, LockCommand, RefreshCommand,
            CopyCommand, CopyCodeCommand, EditCommand, RenewCommand, TombstoneCommand,
            ApplyEditorCommand, EnrollHelloCommand, ForgetHelloCommand, RetryBrokerCommand,
        })
        {
            (command as RelayCommand)?.RaiseCanExecuteChanged();
            (command as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        }
    }
}
