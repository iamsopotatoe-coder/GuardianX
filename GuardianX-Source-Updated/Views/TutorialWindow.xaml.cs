using System.IO;
using System.Windows;

namespace SecureTaskManager.Views
{
    public partial class TutorialWindow : Window
    {
        private const string ConfigFileName = ".guardianx_config";

        public TutorialWindow()
        {
            InitializeComponent();
        }

        private void GetStarted_Click(object sender, RoutedEventArgs e)
        {
            if (DontShowAgainCheckbox.IsChecked == true)
            {
                SaveConfig();
            }
            this.Close();
        }

        private void SaveConfig()
        {
            try
            {
                string exeDir = System.AppContext.BaseDirectory;
                string configPath = Path.Combine(exeDir, ConfigFileName);
                File.WriteAllText(configPath, "tutorial_shown=true");
            }
            catch
            {
            }
        }

        public static bool ShouldShowTutorial()
        {
            try
            {
                string exeDir = System.AppContext.BaseDirectory;
                string configPath = Path.Combine(exeDir, ConfigFileName);
                return !File.Exists(configPath);
            }
            catch
            {
                return true;
            }
        }
    }
}
