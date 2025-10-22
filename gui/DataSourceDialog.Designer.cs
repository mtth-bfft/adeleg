namespace adeleg.gui
{
    partial class DataSourceDialog
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(DataSourceDialog));
            this.connectButton = new System.Windows.Forms.Button();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.label3 = new System.Windows.Forms.Label();
            this.explicitPassword = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.explicitUserName = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.explicitUserDomain = new System.Windows.Forms.TextBox();
            this.useExplicitCredentials = new System.Windows.Forms.RadioButton();
            this.implicitCredentials = new System.Windows.Forms.RadioButton();
            this.dataSourceTabs = new System.Windows.Forms.TabControl();
            this.ldap = new System.Windows.Forms.TabPage();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.label4 = new System.Windows.Forms.Label();
            this.scanAcrossTrusts = new System.Windows.Forms.ComboBox();
            this.removeExplicitDomain = new System.Windows.Forms.Button();
            this.explicitDomainList = new System.Windows.Forms.ListView();
            this.addExplicitDomain = new System.Windows.Forms.Button();
            this.useExplicitDomainList = new System.Windows.Forms.RadioButton();
            this.currentDomainViaDcLocator = new System.Windows.Forms.RadioButton();
            this.oradad = new System.Windows.Forms.TabPage();
            this.selectedOradadPath = new System.Windows.Forms.TextBox();
            this.showOradadSelectorDialog = new System.Windows.Forms.Button();
            this.oradadHelpText = new System.Windows.Forms.LinkLabel();
            this.oradadSelectorDialog = new System.Windows.Forms.FolderBrowserDialog();
            this.label5 = new System.Windows.Forms.Label();
            this.rememberCredentials = new System.Windows.Forms.CheckBox();
            this.groupBox1.SuspendLayout();
            this.dataSourceTabs.SuspendLayout();
            this.ldap.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.oradad.SuspendLayout();
            this.SuspendLayout();
            // 
            // connectButton
            // 
            this.connectButton.BackColor = System.Drawing.SystemColors.ActiveBorder;
            this.connectButton.BackgroundImageLayout = System.Windows.Forms.ImageLayout.None;
            this.connectButton.Cursor = System.Windows.Forms.Cursors.Hand;
            this.connectButton.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.connectButton.FlatStyle = System.Windows.Forms.FlatStyle.System;
            this.connectButton.Location = new System.Drawing.Point(4, 389);
            this.connectButton.Margin = new System.Windows.Forms.Padding(6);
            this.connectButton.Name = "connectButton";
            this.connectButton.Size = new System.Drawing.Size(452, 23);
            this.connectButton.TabIndex = 0;
            this.connectButton.Text = "Connect";
            this.connectButton.UseVisualStyleBackColor = false;
            this.connectButton.Click += new System.EventHandler(this.Connect_Click);
            // 
            // groupBox1
            // 
            this.groupBox1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox1.Controls.Add(this.label3);
            this.groupBox1.Controls.Add(this.explicitPassword);
            this.groupBox1.Controls.Add(this.label2);
            this.groupBox1.Controls.Add(this.explicitUserName);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Controls.Add(this.explicitUserDomain);
            this.groupBox1.Controls.Add(this.useExplicitCredentials);
            this.groupBox1.Controls.Add(this.implicitCredentials);
            this.groupBox1.Location = new System.Drawing.Point(3, 6);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(439, 148);
            this.groupBox1.TabIndex = 2;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Authentication";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(62, 120);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(59, 13);
            this.label3.TabIndex = 7;
            this.label3.Text = "Password :";
            this.label3.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // explicitPassword
            // 
            this.explicitPassword.Location = new System.Drawing.Point(127, 117);
            this.explicitPassword.Name = "explicitPassword";
            this.explicitPassword.PasswordChar = '*';
            this.explicitPassword.Size = new System.Drawing.Size(287, 20);
            this.explicitPassword.TabIndex = 5;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(60, 94);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(61, 13);
            this.label2.TabIndex = 5;
            this.label2.Text = "User name:";
            this.label2.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // explicitUserName
            // 
            this.explicitUserName.Location = new System.Drawing.Point(127, 91);
            this.explicitUserName.Name = "explicitUserName";
            this.explicitUserName.Size = new System.Drawing.Size(287, 20);
            this.explicitUserName.TabIndex = 4;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(52, 68);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(69, 13);
            this.label1.TabIndex = 3;
            this.label1.Text = "User domain:";
            this.label1.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // explicitUserDomain
            // 
            this.explicitUserDomain.Location = new System.Drawing.Point(127, 65);
            this.explicitUserDomain.Name = "explicitUserDomain";
            this.explicitUserDomain.Size = new System.Drawing.Size(287, 20);
            this.explicitUserDomain.TabIndex = 3;
            // 
            // useExplicitCredentials
            // 
            this.useExplicitCredentials.AutoSize = true;
            this.useExplicitCredentials.Location = new System.Drawing.Point(7, 43);
            this.useExplicitCredentials.Name = "useExplicitCredentials";
            this.useExplicitCredentials.Size = new System.Drawing.Size(125, 17);
            this.useExplicitCredentials.TabIndex = 2;
            this.useExplicitCredentials.Text = "Different credentials :";
            this.useExplicitCredentials.UseVisualStyleBackColor = true;
            this.useExplicitCredentials.CheckedChanged += new System.EventHandler(this.ExplicitCredentials_CheckedChanged);
            // 
            // implicitCredentials
            // 
            this.implicitCredentials.AutoSize = true;
            this.implicitCredentials.Checked = true;
            this.implicitCredentials.Location = new System.Drawing.Point(7, 20);
            this.implicitCredentials.Name = "implicitCredentials";
            this.implicitCredentials.Size = new System.Drawing.Size(122, 17);
            this.implicitCredentials.TabIndex = 2;
            this.implicitCredentials.TabStop = true;
            this.implicitCredentials.Text = "Use current account";
            this.implicitCredentials.UseVisualStyleBackColor = true;
            // 
            // dataSourceTabs
            // 
            this.dataSourceTabs.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.dataSourceTabs.Controls.Add(this.ldap);
            this.dataSourceTabs.Controls.Add(this.oradad);
            this.dataSourceTabs.Location = new System.Drawing.Point(0, 0);
            this.dataSourceTabs.Name = "dataSourceTabs";
            this.dataSourceTabs.SelectedIndex = 0;
            this.dataSourceTabs.Size = new System.Drawing.Size(456, 390);
            this.dataSourceTabs.TabIndex = 0;
            // 
            // ldap
            // 
            this.ldap.Controls.Add(this.groupBox2);
            this.ldap.Controls.Add(this.groupBox1);
            this.ldap.Location = new System.Drawing.Point(4, 22);
            this.ldap.Name = "ldap";
            this.ldap.Padding = new System.Windows.Forms.Padding(3);
            this.ldap.Size = new System.Drawing.Size(448, 364);
            this.ldap.TabIndex = 0;
            this.ldap.Text = "LDAP Live";
            this.ldap.UseVisualStyleBackColor = true;
            // 
            // groupBox2
            // 
            this.groupBox2.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox2.Controls.Add(this.rememberCredentials);
            this.groupBox2.Controls.Add(this.label5);
            this.groupBox2.Controls.Add(this.label4);
            this.groupBox2.Controls.Add(this.scanAcrossTrusts);
            this.groupBox2.Controls.Add(this.removeExplicitDomain);
            this.groupBox2.Controls.Add(this.explicitDomainList);
            this.groupBox2.Controls.Add(this.addExplicitDomain);
            this.groupBox2.Controls.Add(this.useExplicitDomainList);
            this.groupBox2.Controls.Add(this.currentDomainViaDcLocator);
            this.groupBox2.Location = new System.Drawing.Point(3, 160);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(439, 219);
            this.groupBox2.TabIndex = 5;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Domain list";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(9, 152);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(103, 13);
            this.label4.TabIndex = 11;
            this.label4.Text = "Scan delegations in:";
            // 
            // scanAcrossTrusts
            // 
            this.scanAcrossTrusts.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.scanAcrossTrusts.FormattingEnabled = true;
            this.scanAcrossTrusts.Items.AddRange(new object[] {
            "only selected domains",
            "domains crawled within selected forest(s)",
            "domains crawled across all trusts"});
            this.scanAcrossTrusts.Location = new System.Drawing.Point(114, 149);
            this.scanAcrossTrusts.Name = "scanAcrossTrusts";
            this.scanAcrossTrusts.Size = new System.Drawing.Size(195, 21);
            this.scanAcrossTrusts.TabIndex = 10;
            // 
            // removeExplicitDomain
            // 
            this.removeExplicitDomain.Location = new System.Drawing.Point(354, 104);
            this.removeExplicitDomain.Name = "removeExplicitDomain";
            this.removeExplicitDomain.Size = new System.Drawing.Size(60, 33);
            this.removeExplicitDomain.TabIndex = 7;
            this.removeExplicitDomain.Text = "Remove";
            this.removeExplicitDomain.UseVisualStyleBackColor = true;
            this.removeExplicitDomain.Click += new System.EventHandler(this.RemoveExplicitDomain_Click);
            // 
            // explicitDomainList
            // 
            this.explicitDomainList.HideSelection = false;
            this.explicitDomainList.Location = new System.Drawing.Point(27, 66);
            this.explicitDomainList.Name = "explicitDomainList";
            this.explicitDomainList.Size = new System.Drawing.Size(324, 71);
            this.explicitDomainList.TabIndex = 6;
            this.explicitDomainList.UseCompatibleStateImageBehavior = false;
            this.explicitDomainList.View = System.Windows.Forms.View.List;
            // 
            // addExplicitDomain
            // 
            this.addExplicitDomain.Location = new System.Drawing.Point(354, 66);
            this.addExplicitDomain.Name = "addExplicitDomain";
            this.addExplicitDomain.Size = new System.Drawing.Size(60, 33);
            this.addExplicitDomain.TabIndex = 5;
            this.addExplicitDomain.Text = "Add...";
            this.addExplicitDomain.UseVisualStyleBackColor = true;
            this.addExplicitDomain.Click += new System.EventHandler(this.AddExplicitDomain_Click);
            // 
            // useExplicitDomainList
            // 
            this.useExplicitDomainList.AutoSize = true;
            this.useExplicitDomainList.Location = new System.Drawing.Point(7, 45);
            this.useExplicitDomainList.Name = "useExplicitDomainList";
            this.useExplicitDomainList.Size = new System.Drawing.Size(105, 17);
            this.useExplicitDomainList.TabIndex = 1;
            this.useExplicitDomainList.Text = "Specify domains:";
            this.useExplicitDomainList.UseVisualStyleBackColor = true;
            // 
            // currentDomainViaDcLocator
            // 
            this.currentDomainViaDcLocator.AutoSize = true;
            this.currentDomainViaDcLocator.Checked = true;
            this.currentDomainViaDcLocator.Location = new System.Drawing.Point(7, 21);
            this.currentDomainViaDcLocator.Name = "currentDomainViaDcLocator";
            this.currentDomainViaDcLocator.Size = new System.Drawing.Size(109, 17);
            this.currentDomainViaDcLocator.TabIndex = 0;
            this.currentDomainViaDcLocator.TabStop = true;
            this.currentDomainViaDcLocator.Text = "Domain of this PC";
            this.currentDomainViaDcLocator.UseVisualStyleBackColor = true;
            // 
            // oradad
            // 
            this.oradad.Controls.Add(this.selectedOradadPath);
            this.oradad.Controls.Add(this.showOradadSelectorDialog);
            this.oradad.Controls.Add(this.oradadHelpText);
            this.oradad.Location = new System.Drawing.Point(4, 22);
            this.oradad.Name = "oradad";
            this.oradad.Padding = new System.Windows.Forms.Padding(3);
            this.oradad.Size = new System.Drawing.Size(448, 343);
            this.oradad.TabIndex = 1;
            this.oradad.Text = "ORADAD";
            this.oradad.UseVisualStyleBackColor = true;
            // 
            // selectedOradadPath
            // 
            this.selectedOradadPath.Location = new System.Drawing.Point(97, 81);
            this.selectedOradadPath.Name = "selectedOradadPath";
            this.selectedOradadPath.Size = new System.Drawing.Size(331, 20);
            this.selectedOradadPath.TabIndex = 3;
            // 
            // showOradadSelectorDialog
            // 
            this.showOradadSelectorDialog.Location = new System.Drawing.Point(16, 81);
            this.showOradadSelectorDialog.Name = "showOradadSelectorDialog";
            this.showOradadSelectorDialog.Size = new System.Drawing.Size(75, 23);
            this.showOradadSelectorDialog.TabIndex = 2;
            this.showOradadSelectorDialog.Text = "Browse...";
            this.showOradadSelectorDialog.UseVisualStyleBackColor = true;
            this.showOradadSelectorDialog.Click += new System.EventHandler(this.ShowOradadSelectorDialog_Click);
            // 
            // oradadHelpText
            // 
            this.oradadHelpText.AutoSize = true;
            this.oradadHelpText.LinkArea = new System.Windows.Forms.LinkArea(19, 50);
            this.oradadHelpText.Location = new System.Drawing.Point(6, 11);
            this.oradadHelpText.Name = "oradadHelpText";
            this.oradadHelpText.Size = new System.Drawing.Size(444, 55);
            this.oradadHelpText.TabIndex = 1;
            this.oradadHelpText.TabStop = true;
            this.oradadHelpText.Text = resources.GetString("oradadHelpText.Text");
            this.oradadHelpText.UseCompatibleTextRendering = true;
            // 
            // oradadSelectorDialog
            // 
            this.oradadSelectorDialog.Description = "Select the root folder of an extracted ORADAD dump";
            this.oradadSelectorDialog.ShowNewFolderButton = false;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(9, 179);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(115, 13);
            this.label5.TabIndex = 12;
            this.label5.Text = "Remember credentials:";
            // 
            // rememberCredentials
            // 
            this.rememberCredentials.AutoSize = true;
            this.rememberCredentials.Checked = true;
            this.rememberCredentials.CheckState = System.Windows.Forms.CheckState.Checked;
            this.rememberCredentials.Location = new System.Drawing.Point(126, 178);
            this.rememberCredentials.Name = "rememberCredentials";
            this.rememberCredentials.Size = new System.Drawing.Size(15, 14);
            this.rememberCredentials.TabIndex = 13;
            this.rememberCredentials.UseVisualStyleBackColor = true;
            // 
            // DataSourceDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(460, 416);
            this.Controls.Add(this.dataSourceTabs);
            this.Controls.Add(this.connectButton);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.KeyPreview = true;
            this.Name = "DataSourceDialog";
            this.Padding = new System.Windows.Forms.Padding(4);
            this.Text = "Select data source";
            this.KeyDown += new System.Windows.Forms.KeyEventHandler(this.DataSourceDialog_KeyDown);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.dataSourceTabs.ResumeLayout(false);
            this.ldap.ResumeLayout(false);
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.oradad.ResumeLayout(false);
            this.oradad.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button connectButton;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.TextBox explicitUserDomain;
        private System.Windows.Forms.RadioButton useExplicitCredentials;
        private System.Windows.Forms.RadioButton implicitCredentials;
        private System.Windows.Forms.TextBox explicitUserName;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox explicitPassword;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TabControl dataSourceTabs;
        private System.Windows.Forms.TabPage ldap;
        private System.Windows.Forms.TabPage oradad;
        private System.Windows.Forms.FolderBrowserDialog oradadSelectorDialog;
        private System.Windows.Forms.LinkLabel oradadHelpText;
        private System.Windows.Forms.TextBox selectedOradadPath;
        private System.Windows.Forms.Button showOradadSelectorDialog;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.RadioButton currentDomainViaDcLocator;
        private System.Windows.Forms.ListView explicitDomainList;
        private System.Windows.Forms.Button addExplicitDomain;
        private System.Windows.Forms.RadioButton useExplicitDomainList;
        private System.Windows.Forms.Button removeExplicitDomain;
        private System.Windows.Forms.ComboBox scanAcrossTrusts;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.CheckBox rememberCredentials;
    }
}