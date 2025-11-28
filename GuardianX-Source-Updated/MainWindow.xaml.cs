using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using SecureTaskManager.ViewModels;
using SecureTaskManager.Views;

namespace SecureTaskManager
{
    public partial class MainWindow : Window
    {
        private MainViewModel viewModel;

        public MainWindow()
        {
            InitializeComponent();
            viewModel = new MainViewModel();
            viewModel.TabSwitchRequested += OnTabSwitchRequested;
            DataContext = viewModel;
            
            Loaded += MainWindow_Loaded;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            if (TutorialWindow.ShouldShowTutorial())
            {
                var tutorial = new TutorialWindow();
                tutorial.Owner = this;
                tutorial.ShowDialog();
            }
        }

        private void OnTabSwitchRequested(object sender, TabSwitchEventArgs e)
        {
            switch (e.TabName)
            {
                case "Properties":
                    PropertiesTab.Visibility = Visibility.Visible;
                    MainTabControl.SelectedItem = PropertiesTab;
                    break;
                case "Startup":
                    MainTabControl.SelectedItem = StartupTab;
                    if (e.HighlightItem != null && e.HighlightItem is Models.StartupInfo)
                    {
                        // Small delay to ensure UI is updated
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            StartupDataGrid.SelectedItem = e.HighlightItem;
                            StartupDataGrid.UpdateLayout();
                            StartupDataGrid.ScrollIntoView(e.HighlightItem);
                            StartupDataGrid.Focus();
                        }), System.Windows.Threading.DispatcherPriority.ContextIdle);
                    }
                    break;
                case "Processes":
                    PropertiesTab.Visibility = Visibility.Collapsed;
                    MainTabControl.SelectedItem = ProcessesTab;
                    break;
            }
        }

        private void DataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (viewModel.SelectedProcess != null)
            {
                viewModel.ShowPropertiesCommand.Execute(null);
            }
        }
    }
}
