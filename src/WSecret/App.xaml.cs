using Microsoft.UI.Xaml;

namespace WSecret;

/// <summary>
/// Application object for the Quick Access shell. Owns the single main window
/// and the activation plumbing; all broker/process work lives elsewhere.
/// </summary>
public partial class App : Application
{
    private static MainWindow? s_shell;

    public App() => InitializeComponent();

    protected override void OnLaunched(LaunchActivatedEventArgs args) => ShowShell();

    /// <summary>
    /// Creates (once) and foregrounds the shell window. Called for launch
    /// activation, hotkey presses, tray commands, and single-instance
    /// redirection from another process.
    /// </summary>
    internal static void ShowShell()
    {
        if (s_shell is null)
        {
            s_shell = new MainWindow();
        }

        s_shell.Activate();
        s_shell.ShowFromAnywhere();
    }

    /// <summary>
    /// Handles activation redirected from another instance. May arrive on a
    /// non-UI thread; the window is only ever created from OnLaunched, so if it
    /// does not exist yet the pending launch will show it momentarily.
    /// </summary>
    internal static void HandleExternalActivation()
    {
        MainWindow? shell = s_shell;
        if (shell is null)
        {
            return;
        }

        shell.DispatcherQueue.TryEnqueue(() =>
        {
            shell.Activate();
            shell.ShowFromAnywhere();
        });
    }
}
