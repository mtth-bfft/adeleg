using adeleg.engine;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.DirectoryServices.ActiveDirectory;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace adeleg.gui
{
    public partial class AddExplicitDomainDialog : Form
    {
        public DomainConfig configuredDomain;

        public AddExplicitDomainDialog()
        {
            InitializeComponent();
        }

        private void implicitCredentials_CheckedChanged(object sender, EventArgs e)
        {
            this.explicitUserDomain.Enabled = this.useExplicitCredentials.Checked;
            this.explicitUserName.Enabled = this.useExplicitCredentials.Checked;
            this.explicitPassword.Enabled = this.useExplicitCredentials.Checked;
        }

        private void useDcLocator_CheckedChanged(object sender, EventArgs e)
        {
            this.dclocatorDnsName.Enabled = this.useDcLocator.Checked;
            this.explicitServerHostname.Enabled = !this.useDcLocator.Checked;
            this.explicitServerPort.Enabled = !this.useDcLocator.Checked;
        }

        private void addButton_Click(object sender, EventArgs e)
        {
            if (useExplicitCredentials.Checked && (explicitUserDomain.Text.Length == 0 || explicitUserName.Text.Length == 0 || explicitPassword.Text.Length == 0))
            {
                MessageBox.Show("Please specify a domain, username and password, or switch back to using global credentials", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (useDcLocator.Checked && dclocatorDnsName.Text.Length == 0)
            {
                MessageBox.Show("Please specify a domain name for automatic server discovery, or switch to using a specific server address", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (!useDcLocator.Checked && (explicitServerHostname.Text.Length == 0 || explicitServerPort.Text.Length == 0))
            {
                MessageBox.Show("Please specify a specific server DNS name or IP address, or switch to using automatic server discovery", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (this.useDcLocator.Checked)
            {
                var ctx = new DirectoryContext(DirectoryContextType.Domain, this.dclocatorDnsName.Text);
                try
                {
                    var dc = DomainController.FindOne(ctx, LocatorOptions.ForceRediscovery | LocatorOptions.WriteableRequired);
                    configuredDomain.server = dc.IPAddress;
                    configuredDomain.port = 389;
                }
                catch (Exception exc)
                {
                    MessageBox.Show($"Unable to find a domain controller in domain {this.dclocatorDnsName.Text}, please specify one manually ({exc.Message})", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            else
            {
                configuredDomain.server = this.explicitServerHostname.Text;
                if (!ushort.TryParse(this.explicitServerPort.Text, out configuredDomain.port))
                {
                    MessageBox.Show("Please enter a valid LDAP port", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            configuredDomain.domainName = (this.useDcLocator.Checked ? this.dclocatorDnsName.Text : "");
            configuredDomain.userDomain = (this.useExplicitCredentials.Checked ? this.explicitUserDomain.Text : "");
            configuredDomain.userName = (this.useExplicitCredentials.Checked ? this.explicitUserName.Text : "");
            configuredDomain.userPassword = (this.useExplicitCredentials.Checked ? this.explicitPassword.Text : "");
            this.DialogResult = DialogResult.OK;
            this.Close();
        }
    }
}
