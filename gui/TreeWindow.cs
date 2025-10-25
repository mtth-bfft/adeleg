using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using adeleg.engine;
using adeleg.engine.connector;

namespace adeleg.gui
{
    public partial class TreeWindow : Form
    {
        private readonly HashSet<string> partitionDNs;
        private bool viewByResource = false;
        private bool viewBuiltInDelegations = false;
        private bool viewTier0AccessRights = false;
        private List<Result> allResults;
        private Dictionary<string, TreeNode> dnToTreeNode = new Dictionary<string, TreeNode>();

        public TreeWindow(List<Result> results, IEnumerable<string> partitionDNs)
        {
            InitializeComponent();
            this.partitionDNs = new HashSet<string>();
            foreach (string partitionDN in partitionDNs)
            {
                this.partitionDNs.Add(partitionDN.ToLower());
            }
            this.allResults = results;
            RedrawTreeFromResults();
            RedrawGridViewFromSelection();

            foreach (TreeNode node in sideTreeView.Nodes)
            {
                if ((string)node.Tag == "Global")
                {
                    sideTreeView.SelectedNode = node;
                    break;
                }
            }
        }

        private TreeNode AddNodeToTreeView(string dn, ObjectClass objClass)
        {
            TreeNode newNode = null;
            this.dnToTreeNode.TryGetValue(dn, out newNode);
            if (newNode != null)
                return newNode;

            Tuple<string, string> split = Utils.SplitDn(dn, partitionDNs);
            string rdn = split.Item1;
            string parentDN = split.Item2;
            int imageIndex = (objClass == ObjectClass.DomainRoot ? 0 :
                (objClass == ObjectClass.User ? 4 :
                (objClass == ObjectClass.Computer ? 5 :
                (objClass == ObjectClass.Group ? 6 :
                (objClass == ObjectClass.Container ? 1 : 3)))));

            newNode = new TreeNode(rdn, imageIndex, imageIndex);
            // TODO: color nodes based on the worst Result within that node's subtree
            newNode.Tag = dn;
            this.dnToTreeNode.Add(dn, newNode);

            if (parentDN == null)
            {
                this.sideTreeView.Nodes.Add(newNode);
            }
            else
            {
                TreeNode parentNode = null;
                this.dnToTreeNode.TryGetValue(parentDN, out parentNode);
                if (parentNode == null)
                {
                    ObjectClass parentClass = (this.partitionDNs.Contains(parentDN.ToLower()) ? ObjectClass.DomainRoot : ObjectClass.Container);
                    parentNode = this.AddNodeToTreeView(parentDN, parentClass);
                }

                parentNode.Nodes.Add(newNode);
            }
            return newNode;
        }

        public void RedrawTreeFromResults()
        {
            this.perResourceToolStripMenuItem.Checked = this.viewByResource;
            this.perTrusteeToolStripMenuItem.Checked = !this.viewByResource;

            this.statusLabel.Text = $"{allResults.Count} results";

            this.dnToTreeNode.Clear();

            this.sideTreeView.BeginUpdate();
            this.sideTreeView.Nodes.Clear();
            foreach (Result res in this.allResults)
            {
                if (!viewTier0AccessRights && res.Trustee.IsTier0)
                    continue; // TODO: replace "verbose" which means nothing -> "tier0" and "removed ACEs"

                if (this.viewByResource)
                {
                    this.AddNodeToTreeView(res.ResourceHierarchicalDisplayName, res.LocationType);
                }
                else
                {
                    this.AddNodeToTreeView(res.TrusteeHierarchicalDisplayName, res.TrusteeType);
                }
            }
            this.sideTreeView.EndUpdate();
        }

        private void RedrawGridViewFromSelection()
        {
            this.resultsDataGrid.Columns.Clear();
            this.resultsDataGrid.AutoGenerateColumns = false;
            this.resultsDataGrid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;

            DataGridViewCell cellTemplate = new DataGridViewTextBoxCell();
            cellTemplate.Style.WrapMode = DataGridViewTriState.True;

            if (this.viewByResource)
            {
                DataGridViewColumn col = new DataGridViewImageColumn();
                col.DataPropertyName = "trusteeType";
                col.HeaderText = "";
                col.Name = "trusteeType";
                col.SortMode = DataGridViewColumnSortMode.Automatic;
                col.AutoSizeMode = DataGridViewAutoSizeColumnMode.None;
                col.Width = this.iconList.ImageSize.Width + 15;
                col.ReadOnly = true;
                col.CellTemplate = new DataGridViewImageCell(false);
                this.resultsDataGrid.Columns.Add(col);

                col = new DataGridViewColumn();
                col.DataPropertyName = "trusteeHierarchicalDisplayName";
                col.HeaderText = "Trustee";
                col.Name = "trusteeHierarchicalDisplayName";
                col.SortMode = DataGridViewColumnSortMode.Automatic;
                col.CellTemplate = cellTemplate;
                this.resultsDataGrid.Columns.Add(col);

                col = new DataGridViewColumn();
                col.DataPropertyName = "text";
                col.HeaderText = "Details";
                col.Name = "text";
                col.SortMode = DataGridViewColumnSortMode.Automatic;
                col.CellTemplate = cellTemplate;
                col.CellTemplate.Style.WrapMode = DataGridViewTriState.True;
                this.resultsDataGrid.Columns.Add(col);
            }
            else
            {
                DataGridViewColumn col = new DataGridViewImageColumn();
                col.DataPropertyName = "locationType";
                col.HeaderText = "";
                col.Name = "locationType";
                col.SortMode = DataGridViewColumnSortMode.Automatic;
                col.AutoSizeMode = DataGridViewAutoSizeColumnMode.None;
                col.Width = this.iconList.ImageSize.Width + 15;
                col.ReadOnly = true;
                col.CellTemplate = new DataGridViewImageCell(false);
                this.resultsDataGrid.Columns.Add(col);

                col = new DataGridViewColumn();
                col.DataPropertyName = "resourceHierarchicalDisplayName";
                col.HeaderText = "Resource";
                col.Name = "resourceHierarchicalDisplayName";
                col.SortMode = DataGridViewColumnSortMode.Automatic;
                col.CellTemplate = cellTemplate;
                this.resultsDataGrid.Columns.Add(col);

                col = new DataGridViewColumn(); //TODO: DataGridViewRichTextBoxColumn();
                col.DataPropertyName = "text";
                col.HeaderText = "Details";
                col.Name = "text";
                col.SortMode = DataGridViewColumnSortMode.Automatic;
                col.CellTemplate = cellTemplate;
                this.resultsDataGrid.Columns.Add(col);
            }

            TreeNode selected = this.sideTreeView.SelectedNode;
            string selectedText = selected == null ? null : (string)selected.Tag;

            List<Result> updatedList = new List<Result>();
            foreach (Result res in this.allResults)
            {   
                if (viewByResource && res.ResourceHierarchicalDisplayName != selectedText)
                    continue;
                if (!viewByResource && res.TrusteeHierarchicalDisplayName != selectedText)
                    continue;
                if (!viewTier0AccessRights && res.Trustee.IsTier0)
                    continue;

                updatedList.Add(res);
            }
            resultsDataGrid.DataSource = updatedList;
            resultsDataGrid.ClearSelection();
        }

        private void quitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void perResourceToolStripMenuItem_Click(object sender, EventArgs e)
        {
            viewByResource = true;
            RedrawTreeFromResults();
        }

        private void perTrusteeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            viewByResource = false;
            RedrawTreeFromResults();
        }

        private void sideTreeView_AfterSelect(object sender, TreeViewEventArgs e)
        {
            RedrawGridViewFromSelection();
        }

        private int GetIconIndexForObjectClass(ObjectClass objClass)
        {
            switch (objClass)
            {
                case ObjectClass.DomainRoot:
                    return 0;
                case ObjectClass.User:
                    return 4;
                case ObjectClass.Computer:
                    return 5;
                case ObjectClass.Container:
                    return 1;
                case ObjectClass.Group:
                    return 6;
                default:
                    return 3;
            }
        }

        private void resultsDataGrid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            Result res = (Result)this.resultsDataGrid.Rows[e.RowIndex].DataBoundItem;

            if (this.resultsDataGrid.Columns[e.ColumnIndex].Name == "locationType")
            {
                if (res.LocationType != ObjectClass.Container)
                {
                    e.CellStyle.BackColor = Color.Yellow;
                }
                e.Value = this.iconList.Images[GetIconIndexForObjectClass(res.LocationType)];
            }
            else if (this.resultsDataGrid.Columns[e.ColumnIndex].Name == "trusteeType")
            {
                if (res.TrusteeType != ObjectClass.Group)
                {
                    e.CellStyle.BackColor = Color.Yellow;
                }
                e.Value = this.iconList.Images[GetIconIndexForObjectClass(res.TrusteeType)];
            }

            if (res.Errors != null && res.Errors.Count > 0)
                e.CellStyle.BackColor = Color.Red;
            else if (res.Warnings != null && res.Warnings.Count > 0)
                e.CellStyle.BackColor = Color.Yellow;
        }

        private void showBuiltinDelegationsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            viewBuiltInDelegations = !viewBuiltInDelegations;
            showBuiltinDelegationsToolStripMenuItem.Checked = viewBuiltInDelegations;

            RedrawTreeFromResults();
            RedrawGridViewFromSelection();
        }

        private void showTier0AccessRightsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            viewTier0AccessRights = !viewTier0AccessRights;
            showTier0AccessRightsToolStripMenuItem.Checked = viewTier0AccessRights;

            RedrawTreeFromResults();
            RedrawGridViewFromSelection();
        }
    }
}
