using System;
using System.Windows;

namespace SecureTaskManager
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            if (!IsAdministrator())
            {
                MessageBox.Show("This application requires administrator privileges to function properly.\n\n" +
                              "Please restart the application as Administrator.",
                              "Administrator Required",
                              MessageBoxButton.OK,
                              MessageBoxImage.Warning);
            }
        }

        private bool IsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}
