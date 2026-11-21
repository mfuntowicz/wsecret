using Microsoft.Windows.AppLifecycle;

using Windows.ApplicationModel.Activation;

namespace WSecret;

/// <summary>
/// Process entry point. Guarantees exactly one Quick Access instance per user
/// session: the first process registers a keyed AppInstance and starts the
/// WinUI application; any later activation is redirected to the first process
/// and the duplicate exits without creating a window or a broker.
/// </summary>
internal static class Program
{
    /// <summary>
    /// Single-instance key. AppInstance uses the package identity for
    /// isolation; no broker IPC endpoint is created here — the broker channel
    /// stays a private inherited anonymous-pipe pair.
    /// </summary>
    private const string SingleInstanceKey = "WSecret.QuickAccess.Main";

    [STAThread]
    private static void Main(string[] args)
    {
        WinRT.ComWrappersSupport.InitializeComWrappers();

        AppInstance current = AppInstance.GetCurrent();
        AppInstance main = AppInstance.FindOrRegisterForKey(SingleInstanceKey);

        if (!main.IsCurrent)
        {
            // Another instance owns the key: hand over this activation and
            // leave. Bounded wait so a hung owner cannot strand this process.
            try
            {
                main.RedirectActivationToAsync(current.GetActivatedEventArgs())
                    .AsTask()
                    .Wait(TimeSpan.FromSeconds(5));
            }
            catch (Exception)
            {
                // Nothing safe to do: the owner is unreachable. Exit silently
                // rather than spawning a second, conflicting shell.
            }

            return;
        }

        main.Activated += OnInstanceActivated;
        Microsoft.UI.Xaml.Application.Start(_ => new App());
    }

    // AppInstance.Activated is EventHandler<AppActivationArguments>: the sender
    // parameter is object, not AppInstance.
    private static void OnInstanceActivated(object? sender, AppActivationArguments args) =>
        App.HandleExternalActivation();
}
