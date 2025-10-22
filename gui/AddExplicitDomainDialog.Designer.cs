namespace adeleg.gui
{
    partial class AddExplicitDomainDialog
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AddExplicitDomainDialog));
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.label3 = new System.Windows.Forms.Label();
            this.explicitPassword = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.explicitUserName = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.explicitUserDomain = new System.Windows.Forms.TextBox();
            this.useExplicitCredentials = new System.Windows.Forms.RadioButton();
            this.useGlobalCredentials = new System.Windows.Forms.RadioButton();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.useDcLocator = new System.Windows.Forms.RadioButton();
            this.label5 = new System.Windows.Forms.Label();
            this.explicitServerPort = new System.Windows.Forms.TextBox();
            this.explicitServerHostname = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.dclocatorDnsName = new System.Windows.Forms.TextBox();
            this.useExplicitAddress = new System.Windows.Forms.RadioButton();
            this.label6 = new System.Windows.Forms.Label();
            this.addButton = new System.Windows.Forms.Button();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.SuspendLayout();
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
            this.groupBox1.Controls.Add(this.useGlobalCredentials);
            this.groupBox1.Location = new System.Drawing.Point(5, 8);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(345, 148);
            this.groupBox1.TabIndex = 3;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Authentication";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(52, 118);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(56, 13);
            this.label3.TabIndex = 7;
            this.label3.Text = "Password:";
            this.label3.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // explicitPassword
            // 
            this.explicitPassword.Enabled = false;
            this.explicitPassword.Location = new System.Drawing.Point(111, 115);
            this.explicitPassword.Name = "explicitPassword";
            this.explicitPassword.PasswordChar = '*';
            this.explicitPassword.Size = new System.Drawing.Size(223, 20);
            this.explicitPassword.TabIndex = 5;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(50, 92);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(58, 13);
            this.label2.TabIndex = 5;
            this.label2.Text = "Username:";
            this.label2.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // explicitUserName
            // 
            this.explicitUserName.Enabled = false;
            this.explicitUserName.Location = new System.Drawing.Point(111, 89);
            this.explicitUserName.Name = "explicitUserName";
            this.explicitUserName.Size = new System.Drawing.Size(223, 20);
            this.explicitUserName.TabIndex = 4;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(62, 66);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(46, 13);
            this.label1.TabIndex = 3;
            this.label1.Text = "Domain:";
            this.label1.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // explicitUserDomain
            // 
            this.explicitUserDomain.Enabled = false;
            this.explicitUserDomain.Location = new System.Drawing.Point(111, 63);
            this.explicitUserDomain.Name = "explicitUserDomain";
            this.explicitUserDomain.Size = new System.Drawing.Size(223, 20);
            this.explicitUserDomain.TabIndex = 3;
            // 
            // useExplicitCredentials
            // 
            this.useExplicitCredentials.AutoSize = true;
            this.useExplicitCredentials.Location = new System.Drawing.Point(7, 41);
            this.useExplicitCredentials.Name = "useExplicitCredentials";
            this.useExplicitCredentials.Size = new System.Drawing.Size(120, 17);
            this.useExplicitCredentials.TabIndex = 2;
            this.useExplicitCredentials.Text = "Specific credentials:";
            this.useExplicitCredentials.UseVisualStyleBackColor = true;
            // 
            // useGlobalCredentials
            // 
            this.useGlobalCredentials.AutoSize = true;
            this.useGlobalCredentials.Checked = true;
            this.useGlobalCredentials.Location = new System.Drawing.Point(7, 20);
            this.useGlobalCredentials.Name = "useGlobalCredentials";
            this.useGlobalCredentials.Size = new System.Drawing.Size(114, 17);
            this.useGlobalCredentials.TabIndex = 2;
            this.useGlobalCredentials.TabStop = true;
            this.useGlobalCredentials.Text = "Use global settings";
            this.useGlobalCredentials.UseVisualStyleBackColor = true;
            this.useGlobalCredentials.CheckedChanged += new System.EventHandler(this.implicitCredentials_CheckedChanged);
            // 
            // groupBox2
            // 
            this.groupBox2.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox2.Controls.Add(this.label6);
            this.groupBox2.Controls.Add(this.useExplicitAddress);
            this.groupBox2.Controls.Add(this.label4);
            this.groupBox2.Controls.Add(this.useDcLocator);
            this.groupBox2.Controls.Add(this.dclocatorDnsName);
            this.groupBox2.Controls.Add(this.label5);
            this.groupBox2.Controls.Add(this.explicitServerPort);
            this.groupBox2.Controls.Add(this.explicitServerHostname);
            this.groupBox2.Location = new System.Drawing.Point(5, 160);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(345, 142);
            this.groupBox2.TabIndex = 8;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Server";
            // 
            // useDcLocator
            // 
            this.useDcLocator.AutoSize = true;
            this.useDcLocator.Checked = true;
            this.useDcLocator.Location = new System.Drawing.Point(7, 20);
            this.useDcLocator.Name = "useDcLocator";
            this.useDcLocator.Size = new System.Drawing.Size(164, 17);
            this.useDcLocator.TabIndex = 6;
            this.useDcLocator.TabStop = true;
            this.useDcLocator.Text = "Find a server automatically in:";
            this.useDcLocator.UseVisualStyleBackColor = true;
            this.useDcLocator.CheckedChanged += new System.EventHandler(this.useDcLocator_CheckedChanged);
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(110, 120);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(29, 13);
            this.label5.TabIndex = 5;
            this.label5.Text = "Port:";
            this.label5.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // explicitServerPort
            // 
            this.explicitServerPort.Enabled = false;
            this.explicitServerPort.Location = new System.Drawing.Point(142, 117);
            this.explicitServerPort.Name = "explicitServerPort";
            this.explicitServerPort.Size = new System.Drawing.Size(49, 20);
            this.explicitServerPort.TabIndex = 4;
            this.explicitServerPort.Text = "389";
            // 
            // explicitServerHostname
            // 
            this.explicitServerHostname.Enabled = false;
            this.explicitServerHostname.Location = new System.Drawing.Point(142, 91);
            this.explicitServerHostname.Name = "explicitServerHostname";
            this.explicitServerHostname.Size = new System.Drawing.Size(192, 20);
            this.explicitServerHostname.TabIndex = 3;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(38, 46);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(101, 13);
            this.label4.TabIndex = 8;
            this.label4.Text = "Domain DNS name:";
            this.label4.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // dclocatorDnsName
            // 
            this.dclocatorDnsName.Location = new System.Drawing.Point(142, 43);
            this.dclocatorDnsName.Name = "dclocatorDnsName";
            this.dclocatorDnsName.Size = new System.Drawing.Size(192, 20);
            this.dclocatorDnsName.TabIndex = 9;
            // 
            // useExplicitAddress
            // 
            this.useExplicitAddress.AutoSize = true;
            this.useExplicitAddress.Location = new System.Drawing.Point(7, 71);
            this.useExplicitAddress.Name = "useExplicitAddress";
            this.useExplicitAddress.Size = new System.Drawing.Size(127, 17);
            this.useExplicitAddress.TabIndex = 10;
            this.useExplicitAddress.Text = "Use a specific server:";
            this.useExplicitAddress.UseVisualStyleBackColor = true;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(56, 94);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(83, 13);
            this.label6.TabIndex = 11;
            this.label6.Text = "Hostname or IP:";
            this.label6.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // addButton
            // 
            this.addButton.BackColor = System.Drawing.SystemColors.ActiveBorder;
            this.addButton.BackgroundImageLayout = System.Windows.Forms.ImageLayout.None;
            this.addButton.Cursor = System.Windows.Forms.Cursors.Hand;
            this.addButton.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.addButton.FlatStyle = System.Windows.Forms.FlatStyle.System;
            this.addButton.Location = new System.Drawing.Point(5, 306);
            this.addButton.Margin = new System.Windows.Forms.Padding(6);
            this.addButton.Name = "addButton";
            this.addButton.Size = new System.Drawing.Size(345, 23);
            this.addButton.TabIndex = 12;
            this.addButton.Text = "Add";
            this.addButton.UseVisualStyleBackColor = false;
            this.addButton.Click += new System.EventHandler(this.addButton_Click);
            // 
            // AddExplicitDomainDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(355, 334);
            this.Controls.Add(this.addButton);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "AddExplicitDomainDialog";
            this.Padding = new System.Windows.Forms.Padding(5);
            this.Text = "Add a domain";
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox explicitPassword;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox explicitUserName;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox explicitUserDomain;
        private System.Windows.Forms.RadioButton useExplicitCredentials;
        private System.Windows.Forms.RadioButton useGlobalCredentials;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TextBox explicitServerPort;
        private System.Windows.Forms.TextBox explicitServerHostname;
        private System.Windows.Forms.RadioButton useDcLocator;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox dclocatorDnsName;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.RadioButton useExplicitAddress;
        private System.Windows.Forms.Button addButton;
    }
}