namespace adeleg.gui
{
    partial class TreeWindow
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
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(TreeWindow));
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.quitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.modeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.perResourceToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.perTrusteeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.refreshToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.refreshSelectedContainerToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.refreshSchemaAndGlobalMetadataToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.viewToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.showBuiltinDelegationsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.showTier0AccessRightsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutADelegToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.sideTreeView = new System.Windows.Forms.TreeView();
            this.iconList = new System.Windows.Forms.ImageList(this.components);
            this.resultsDataGrid = new System.Windows.Forms.DataGridView();
            this.statusStrip = new System.Windows.Forms.StatusStrip();
            this.progressBar = new System.Windows.Forms.ToolStripProgressBar();
            this.statusLabel = new System.Windows.Forms.ToolStripStatusLabel();
            this.tableLayout = new System.Windows.Forms.TableLayoutPanel();
            this.showMissingACLEntriesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.menuStrip1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.resultsDataGrid)).BeginInit();
            this.statusStrip.SuspendLayout();
            this.tableLayout.SuspendLayout();
            this.SuspendLayout();
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem,
            this.modeToolStripMenuItem,
            this.refreshToolStripMenuItem,
            this.viewToolStripMenuItem,
            this.aboutToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(1056, 24);
            this.menuStrip1.TabIndex = 0;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // fileToolStripMenuItem
            // 
            this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.quitToolStripMenuItem});
            this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            this.fileToolStripMenuItem.Size = new System.Drawing.Size(37, 20);
            this.fileToolStripMenuItem.Text = "File";
            // 
            // quitToolStripMenuItem
            // 
            this.quitToolStripMenuItem.Name = "quitToolStripMenuItem";
            this.quitToolStripMenuItem.Size = new System.Drawing.Size(97, 22);
            this.quitToolStripMenuItem.Text = "Quit";
            this.quitToolStripMenuItem.Click += new System.EventHandler(this.quitToolStripMenuItem_Click);
            // 
            // modeToolStripMenuItem
            // 
            this.modeToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.perResourceToolStripMenuItem,
            this.perTrusteeToolStripMenuItem});
            this.modeToolStripMenuItem.Name = "modeToolStripMenuItem";
            this.modeToolStripMenuItem.Size = new System.Drawing.Size(50, 20);
            this.modeToolStripMenuItem.Text = "Mode";
            // 
            // perResourceToolStripMenuItem
            // 
            this.perResourceToolStripMenuItem.Name = "perResourceToolStripMenuItem";
            this.perResourceToolStripMenuItem.Size = new System.Drawing.Size(139, 22);
            this.perResourceToolStripMenuItem.Text = "Per resource";
            this.perResourceToolStripMenuItem.Click += new System.EventHandler(this.perResourceToolStripMenuItem_Click);
            // 
            // perTrusteeToolStripMenuItem
            // 
            this.perTrusteeToolStripMenuItem.Name = "perTrusteeToolStripMenuItem";
            this.perTrusteeToolStripMenuItem.Size = new System.Drawing.Size(139, 22);
            this.perTrusteeToolStripMenuItem.Text = "Per trustee";
            this.perTrusteeToolStripMenuItem.Click += new System.EventHandler(this.perTrusteeToolStripMenuItem_Click);
            // 
            // refreshToolStripMenuItem
            // 
            this.refreshToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.refreshSelectedContainerToolStripMenuItem,
            this.refreshSchemaAndGlobalMetadataToolStripMenuItem});
            this.refreshToolStripMenuItem.Name = "refreshToolStripMenuItem";
            this.refreshToolStripMenuItem.Size = new System.Drawing.Size(58, 20);
            this.refreshToolStripMenuItem.Text = "Refresh";
            // 
            // refreshSelectedContainerToolStripMenuItem
            // 
            this.refreshSelectedContainerToolStripMenuItem.Name = "refreshSelectedContainerToolStripMenuItem";
            this.refreshSelectedContainerToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F5;
            this.refreshSelectedContainerToolStripMenuItem.Size = new System.Drawing.Size(269, 22);
            this.refreshSelectedContainerToolStripMenuItem.Text = "Refresh selected object";
            // 
            // refreshSchemaAndGlobalMetadataToolStripMenuItem
            // 
            this.refreshSchemaAndGlobalMetadataToolStripMenuItem.Name = "refreshSchemaAndGlobalMetadataToolStripMenuItem";
            this.refreshSchemaAndGlobalMetadataToolStripMenuItem.Size = new System.Drawing.Size(269, 22);
            this.refreshSchemaAndGlobalMetadataToolStripMenuItem.Text = "Refresh schema and global metadata";
            // 
            // viewToolStripMenuItem
            // 
            this.viewToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.showBuiltinDelegationsToolStripMenuItem,
            this.showTier0AccessRightsToolStripMenuItem,
            this.showMissingACLEntriesToolStripMenuItem});
            this.viewToolStripMenuItem.Name = "viewToolStripMenuItem";
            this.viewToolStripMenuItem.Size = new System.Drawing.Size(44, 20);
            this.viewToolStripMenuItem.Text = "View";
            // 
            // showBuiltinDelegationsToolStripMenuItem
            // 
            this.showBuiltinDelegationsToolStripMenuItem.Name = "showBuiltinDelegationsToolStripMenuItem";
            this.showBuiltinDelegationsToolStripMenuItem.Size = new System.Drawing.Size(262, 22);
            this.showBuiltinDelegationsToolStripMenuItem.Text = "Show built-in delegations";
            this.showBuiltinDelegationsToolStripMenuItem.Click += new System.EventHandler(this.showBuiltinDelegationsToolStripMenuItem_Click);
            // 
            // showTier0AccessRightsToolStripMenuItem
            // 
            this.showTier0AccessRightsToolStripMenuItem.Name = "showTier0AccessRightsToolStripMenuItem";
            this.showTier0AccessRightsToolStripMenuItem.Size = new System.Drawing.Size(262, 22);
            this.showTier0AccessRightsToolStripMenuItem.Text = "Show delegations for Tier-0 trustees";
            this.showTier0AccessRightsToolStripMenuItem.Click += new System.EventHandler(this.showTier0AccessRightsToolStripMenuItem_Click);
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.aboutADelegToolStripMenuItem});
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(52, 20);
            this.aboutToolStripMenuItem.Text = "About";
            // 
            // aboutADelegToolStripMenuItem
            // 
            this.aboutADelegToolStripMenuItem.Name = "aboutADelegToolStripMenuItem";
            this.aboutADelegToolStripMenuItem.Size = new System.Drawing.Size(157, 22);
            this.aboutADelegToolStripMenuItem.Text = "About ADeleg...";
            // 
            // splitContainer1
            // 
            this.splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer1.Location = new System.Drawing.Point(3, 3);
            this.splitContainer1.Name = "splitContainer1";
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.sideTreeView);
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.resultsDataGrid);
            this.splitContainer1.Size = new System.Drawing.Size(1050, 577);
            this.splitContainer1.SplitterDistance = 350;
            this.splitContainer1.TabIndex = 1;
            // 
            // sideTreeView
            // 
            this.sideTreeView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.sideTreeView.HideSelection = false;
            this.sideTreeView.ImageIndex = 0;
            this.sideTreeView.ImageList = this.iconList;
            this.sideTreeView.Location = new System.Drawing.Point(0, 0);
            this.sideTreeView.Name = "sideTreeView";
            this.sideTreeView.SelectedImageIndex = 0;
            this.sideTreeView.Size = new System.Drawing.Size(350, 577);
            this.sideTreeView.TabIndex = 0;
            this.sideTreeView.AfterSelect += new System.Windows.Forms.TreeViewEventHandler(this.sideTreeView_AfterSelect);
            // 
            // iconList
            // 
            this.iconList.ImageStream = ((System.Windows.Forms.ImageListStreamer)(resources.GetObject("iconList.ImageStream")));
            this.iconList.TransparentColor = System.Drawing.Color.Transparent;
            this.iconList.Images.SetKeyName(0, "domain.ico");
            this.iconList.Images.SetKeyName(1, "container.ico");
            this.iconList.Images.SetKeyName(2, "ou.ico");
            this.iconList.Images.SetKeyName(3, "external.ico");
            this.iconList.Images.SetKeyName(4, "user.ico");
            this.iconList.Images.SetKeyName(5, "computer.ico");
            this.iconList.Images.SetKeyName(6, "group.ico");
            // 
            // resultsDataGrid
            // 
            this.resultsDataGrid.AllowUserToAddRows = false;
            this.resultsDataGrid.AllowUserToOrderColumns = true;
            this.resultsDataGrid.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.resultsDataGrid.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.resultsDataGrid.Dock = System.Windows.Forms.DockStyle.Fill;
            this.resultsDataGrid.Location = new System.Drawing.Point(0, 0);
            this.resultsDataGrid.Name = "resultsDataGrid";
            this.resultsDataGrid.ReadOnly = true;
            this.resultsDataGrid.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.resultsDataGrid.Size = new System.Drawing.Size(696, 577);
            this.resultsDataGrid.TabIndex = 0;
            this.resultsDataGrid.CellFormatting += new System.Windows.Forms.DataGridViewCellFormattingEventHandler(this.resultsDataGrid_CellFormatting);
            // 
            // statusStrip
            // 
            this.statusStrip.Dock = System.Windows.Forms.DockStyle.Fill;
            this.statusStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.progressBar,
            this.statusLabel});
            this.statusStrip.Location = new System.Drawing.Point(0, 583);
            this.statusStrip.Name = "statusStrip";
            this.statusStrip.Size = new System.Drawing.Size(1056, 22);
            this.statusStrip.SizingGrip = false;
            this.statusStrip.TabIndex = 2;
            this.statusStrip.Text = "Offline";
            // 
            // progressBar
            // 
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(100, 16);
            this.progressBar.Style = System.Windows.Forms.ProgressBarStyle.Continuous;
            // 
            // statusLabel
            // 
            this.statusLabel.Name = "statusLabel";
            this.statusLabel.Size = new System.Drawing.Size(43, 17);
            this.statusLabel.Text = "Offline";
            // 
            // tableLayout
            // 
            this.tableLayout.ColumnCount = 1;
            this.tableLayout.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayout.Controls.Add(this.statusStrip, 0, 1);
            this.tableLayout.Controls.Add(this.splitContainer1, 0, 0);
            this.tableLayout.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayout.Location = new System.Drawing.Point(0, 24);
            this.tableLayout.Name = "tableLayout";
            this.tableLayout.RowCount = 2;
            this.tableLayout.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayout.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayout.Size = new System.Drawing.Size(1056, 605);
            this.tableLayout.TabIndex = 3;
            // 
            // showMissingACLEntriesToolStripMenuItem
            // 
            this.showMissingACLEntriesToolStripMenuItem.Name = "showMissingACLEntriesToolStripMenuItem";
            this.showMissingACLEntriesToolStripMenuItem.Size = new System.Drawing.Size(262, 22);
            this.showMissingACLEntriesToolStripMenuItem.Text = "Show missing ACL entries";
            // 
            // TreeWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1056, 629);
            this.Controls.Add(this.tableLayout);
            this.Controls.Add(this.menuStrip1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "TreeWindow";
            this.Text = "ADeleg";
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.resultsDataGrid)).EndInit();
            this.statusStrip.ResumeLayout(false);
            this.statusStrip.PerformLayout();
            this.tableLayout.ResumeLayout(false);
            this.tableLayout.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem modeToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem perResourceToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem perTrusteeToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem quitToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutADelegToolStripMenuItem;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.TreeView sideTreeView;
        private System.Windows.Forms.StatusStrip statusStrip;
        private System.Windows.Forms.ToolStripProgressBar progressBar;
        private System.Windows.Forms.TableLayoutPanel tableLayout;
        private System.Windows.Forms.ToolStripStatusLabel statusLabel;
        private System.Windows.Forms.ImageList iconList;
        private System.Windows.Forms.DataGridView resultsDataGrid;
        private System.Windows.Forms.ToolStripMenuItem refreshToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem refreshSelectedContainerToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem refreshSchemaAndGlobalMetadataToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem viewToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem showBuiltinDelegationsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem showTier0AccessRightsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem showMissingACLEntriesToolStripMenuItem;
    }
}