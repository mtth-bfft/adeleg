using System;
using System.Windows.Forms;
using System.DirectoryServices.ActiveDirectory;
using adeleg.engine;
using adeleg.engine.connector;
using System.Collections.Generic;
using System.Net;

namespace adeleg.gui
{
    public partial class DataSourceDialog : Form
    {
        public List<IConnector> dataSources = new List<IConnector>();

        public DataSourceDialog()
        {
            InitializeComponent();
            this.DialogResult = DialogResult.Cancel; // default result if user closes the window

            // Pre-fill with previous settings, if any
            Config previousConf = Config.Load();
            this.rememberCredentials.Checked = previousConf.rememberCredentials;
            if (previousConf.dataSourceTab == null || previousConf.dataSourceTab == "ldap")
            {
                this.dataSourceTabs.SelectedIndex = 0;
            }
            else if (previousConf.dataSourceTab == "oradad")
            {
                this.dataSourceTabs.SelectedIndex = 1;
            }
            this.scanAcrossTrusts.SelectedIndex = 0;
            if (previousConf.crawlWithinForest)
            {
                this.scanAcrossTrusts.SelectedIndex++;
            }
            if (previousConf.crawlAllDomains)
            {
                this.scanAcrossTrusts.SelectedIndex++;
            }
            try
            {
                var ctx = new DirectoryContext(DirectoryContextType.Domain);
                var dc = DomainController.FindOne(ctx, LocatorOptions.ForceRediscovery | LocatorOptions.WriteableRequired);
                Console.WriteLine($" [+] Computer is AD-joined, can use DC : {dc}");
                this.currentDomainViaDcLocator.Checked = true;
                this.implicitCredentials.Checked = true;
                this.currentDomainViaDcLocator.Checked = true;
                this.addExplicitDomain.Enabled = false;
                this.removeExplicitDomain.Enabled = false;
                this.ActiveControl = this.connectButton;
            }
            catch (Exception) {
                Console.WriteLine(" [.] Computer is not AD-joined or could not locate a domain controller, please input server path and credentials");
                this.useExplicitCredentials.Checked = true;
                this.useExplicitDomainList.Checked = true;
                this.currentDomainViaDcLocator.Enabled = false;
                this.addExplicitDomain.Enabled = true;
                this.removeExplicitDomain.Enabled = true;
                this.ActiveControl = this.explicitUserDomain;
            }

            if (previousConf.globalUserName != null && previousConf.globalUserName != "")
            {
                useExplicitCredentials.Checked = true;
                explicitUserName.Text = previousConf.globalUserName;
                explicitUserDomain.Text = previousConf.globalUserDomain;
                explicitPassword.Text = previousConf.globalUserPassword;
            }
            if (previousConf.domains != null)
            {
                foreach (DomainConfig toAdd in previousConf.domains)
                {
                    string name = toAdd.server.Length == 0 ? toAdd.domainName : toAdd.server;
                    ListViewItem newItem = new ListViewItem(name)
                    {
                        Name = name,
                        Tag = toAdd
                    };
                    explicitDomainList.Items.Add(newItem);
                }
            }
        }

        private void ExplicitCredentials_CheckedChanged(object sender, EventArgs e)
        {
            this.explicitUserDomain.Enabled = this.useExplicitCredentials.Checked;
            this.explicitUserName.Enabled = this.useExplicitCredentials.Checked;
            this.explicitPassword.Enabled = this.useExplicitCredentials.Checked;
        }

        private void Connect_Click(object sender, EventArgs e)
        {
            // Save config to file so that next time it is already pre-filled with what the user entered
            Config configToSave = new Config
            {
                dataSourceTab = dataSourceTabs.SelectedTab.Name,
                rememberCredentials = this.rememberCredentials.Checked,
                // LDAP live tab
                globalUserDomain = (dataSourceTabs.SelectedTab.Name == "ldap" && this.useExplicitCredentials.Checked) ? this.explicitUserDomain.Text : "",
                globalUserName = (dataSourceTabs.SelectedTab.Name == "ldap" && this.useExplicitCredentials.Checked) ? this.explicitUserName.Text : "",
                globalUserPassword = (dataSourceTabs.SelectedTab.Name == "ldap" && this.useExplicitCredentials.Checked && this.rememberCredentials.Checked) ? this.explicitPassword.Text : "",
                crawlWithinForest = (dataSourceTabs.SelectedTab.Name == "ldap" && this.scanAcrossTrusts.SelectedIndex > 0),
                crawlAllDomains = (dataSourceTabs.SelectedTab.Name == "ldap" && this.scanAcrossTrusts.SelectedIndex > 1),
                domains = new List<DomainConfig>(),
                // ORADAD
                oradadPath = (dataSourceTabs.SelectedTab.Name == "oradad" ? selectedOradadPath.Text : ""),
            };
            if (this.dataSourceTabs.SelectedIndex == 0 && this.useExplicitDomainList.Checked) {
                foreach (ListViewItem item in this.explicitDomainList.Items)
                {
                    DomainConfig domCfg = (DomainConfig)item.Tag;
                    if (!this.rememberCredentials.Checked)
                        domCfg.userPassword = "";
                    configToSave.domains.Add(domCfg);
                }
            }
            configToSave.Save();

            try
            {
                if (this.dataSourceTabs.SelectedTab.Name == "ldap")
                {
                    if (this.useExplicitCredentials.Checked)
                    {
                        if (this.explicitUserName.Text.Length == 0)
                        {
                            MessageBox.Show("Please specify a username to logon as, or switch to built-in implict Windows SSO", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                        if (this.explicitPassword.Text.Length == 0)
                        {
                            MessageBox.Show("Please specify the account password, or switch to built-in implict Windows SSO", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                    }
                    if (this.useExplicitDomainList.Checked && this.explicitDomainList.Items.Count == 0)
                    {
                        MessageBox.Show("Please specify at least one domain, or switch to automatic domain detection", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    List<DomainConfig> domains = new List<DomainConfig>();

                    if (this.currentDomainViaDcLocator.Checked)
                    {
                        var ctx = new DirectoryContext(DirectoryContextType.Domain);
                        var dc = DomainController.FindOne(ctx, LocatorOptions.ForceRediscovery | LocatorOptions.WriteableRequired);

                        DomainConfig newDC;
                        newDC.server = dc.IPAddress;
                        newDC.domainName = "";
                        newDC.port = 389;
                        if (this.useExplicitCredentials.Checked)
                        {
                            newDC.userDomain = this.explicitUserDomain.Text;
                            newDC.userName = this.explicitUserName.Text;
                            newDC.userPassword = this.explicitPassword.Text;
                        }
                        else
                        {
                            newDC.userDomain = newDC.userName = newDC.userPassword = "";
                        }
                        domains.Add(newDC);
                    }
                    else
                    {
                        foreach (ListViewItem item in this.explicitDomainList.Items)
                        {
                            domains.Add((DomainConfig)item.Tag);
                        }
                    }

                    foreach (DomainConfig dom in domains)
                    {
                        NetworkCredential creds = null;
                        if (dom.userDomain != "" || dom.userName != "" || dom.userPassword != "")
                        {
                            string domain = (dom.userDomain == "" ? "." : dom.userDomain);
                            creds = new NetworkCredential(dom.userDomain, dom.userPassword, domain);
                        }
                        else if (this.useExplicitCredentials.Checked)
                        {
                            string domain = (this.explicitUserDomain.Text.Length == 0 ? "." : this.explicitUserDomain.Text);
                            creds = new NetworkCredential(this.explicitUserName.Text, this.explicitPassword.Text, domain);
                        }
                        string server = dom.server;
                        ushort port = dom.port;
                        if (server == "")
                        {
                            try
                            {
                                var ctx = new DirectoryContext(DirectoryContextType.Domain, dom.domainName);
                                var dc = DomainController.FindOne(ctx, LocatorOptions.ForceRediscovery | LocatorOptions.WriteableRequired);
                                server = dc.IPAddress;
                                port = 389;
                            }
                            catch (Exception exc)
                            {
                                MessageBox.Show($"Unable to find a domain controller for '{dom.domainName}' automatically, please specify one ({exc.Message})", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                return;
                            }
                        }
                        dataSources.Add(new LdapLiveConnector(server, port, creds));
                    }

                    if (this.scanAcrossTrusts.SelectedIndex > 0)
                    {
                        try
                        {
                            LdapLiveConnector.CrawlDomainsAcrossTrusts(dataSources, this.scanAcrossTrusts.SelectedIndex > 1);
                        }
                        catch (Exception exc)
                        {
                            MessageBox.Show($"Unable to find a domain controller automatically for a trusted domain, turn off automatic domain enumeration via trusts and specify domain controllers manually ({exc.Message})", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                    }
                }
                else if (this.dataSourceTabs.SelectedTab.Name == "oradad")
                {
                    dataSources.Add(new OradadConnector(this.selectedOradadPath.Text));
                }

                this.DialogResult = DialogResult.OK;
                this.Close();
            }
            catch (Exception exc)
            {
                MessageBox.Show(exc.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }

        private void ShowOradadSelectorDialog_Click(object sender, EventArgs e)
        {
            DialogResult res = this.oradadSelectorDialog.ShowDialog();
            if (res == DialogResult.OK)
            {
                this.selectedOradadPath.Text = this.oradadSelectorDialog.SelectedPath;
            }
        }

        private void AddExplicitDomain_Click(object sender, EventArgs e)
        {
            var addDialog = new AddExplicitDomainDialog();
            DialogResult res = addDialog.ShowDialog();
            if (res == DialogResult.OK)
            {
                DomainConfig toAdd = addDialog.configuredDomain;
                string name = toAdd.server.Length == 0 ? toAdd.domainName : toAdd.server;
                ListViewItem newItem = new ListViewItem(name);
                newItem.Name = name;
                newItem.Tag = toAdd;
                this.explicitDomainList.Items.Add(newItem);
            }
        }

        private void RemoveExplicitDomain_Click(object sender, EventArgs e)
        {
            List<string> toRemove = new List<string>();
            foreach (int selectedIdx in this.explicitDomainList.SelectedIndices)
            {
                toRemove.Add(this.explicitDomainList.Items[selectedIdx].Text);
            }
            foreach (string name in toRemove)
            {
                this.explicitDomainList.Items.RemoveByKey(name);
            }
        }

        private void DataSourceDialog_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                this.Connect_Click(sender, null);
            }
        }
    }
}