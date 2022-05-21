extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use std::collections::{HashMap, HashSet};
use std::cell::RefCell;
use stretch::{geometry::{Rect, Size}, style::{Overflow, FlexDirection, FlexWrap, Dimension, PositionType, Style}};
use nwg::{NativeUi, OemIcon};
use nwd::NwgUi;
use winldap::connection::{LdapCredentials, LdapConnection};
use authz::{Ace, Sid};
use crate::delegations::{DelegationLocation, Delegation, DelegationRights};
use crate::engine::{Engine, BUILTIN_ACES};
use crate::error::AdelegError;
use crate::AdelegResult;
use crate::utils::{ends_with_case_insensitive, replace_suffix_case_insensitive};

#[derive(Default, NwgUi)]
pub struct BasicApp {
    engine: Option<RefCell<Engine<'static>>>,
    template_file_paths: Option<RefCell<Vec<String>>>,
    delegation_file_paths: Option<RefCell<Vec<String>>>,
    results: Option<RefCell<HashMap<DelegationLocation, Result<AdelegResult, AdelegError>>>>,
    view_by_trustee: RefCell<bool>,

    #[nwg_control(maximized: true, title: "ADeleg", flags: "MAIN_WINDOW|VISIBLE")]
    #[nwg_events(
        OnWindowClose: [BasicApp::cleanup],
        OnInit: [BasicApp::init],
    )]
    window: nwg::Window,

    #[nwg_control(parent: window, text: "File")]
    menu_file: nwg::Menu,

    #[nwg_control(parent: menu_file, text: "Load...")]
    menu_item_load: nwg::Menu,

    #[nwg_control(parent: menu_item_load, text: "Templates...")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::show_template_load_dialog] )]
    menu_item_load_templates: nwg::MenuItem,

    #[nwg_control(parent: menu_item_load, text: "Delegations...")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::show_delegation_load_dialog] )]
    menu_item_load_delegations: nwg::MenuItem,

    #[nwg_control(parent: menu_file, text: "Exit")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::cleanup] )]
    menu_item_exit: nwg::MenuItem,

    #[nwg_control(parent: window, text: "View")]
    menu_view: nwg::Menu,

    #[nwg_control(parent: menu_view, text: "Refresh")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::refresh] )]
    menu_item_refresh: nwg::MenuItem,

    #[nwg_control(parent: menu_view, text: "Index view by...")]
    menu_view_index_by: nwg::Menu,

    #[nwg_control(parent: menu_view_index_by, text: "Resources", check: true)]
    #[nwg_events( OnMenuItemSelected: [BasicApp::set_view_index_by_resources] )]
    menu_view_index_by_resources: nwg::MenuItem,

    #[nwg_control(parent: menu_view_index_by, text: "Trustees")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::set_view_index_by_trustees] )]
    menu_view_index_by_trustees: nwg::MenuItem,

    #[nwg_control(parent: window, text: "Help")]
    menu_help: nwg::Menu,

    #[nwg_control(parent: menu_help, text: "About")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::about] )]
    menu_help_about: nwg::MenuItem,

    #[nwg_control(parent: menu_help, text: "Online manual")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::online_help] )]
    menu_help_online: nwg::MenuItem,

    #[nwg_layout(parent: window, flex_direction: FlexDirection::Column, flex_wrap: FlexWrap::Wrap, overflow: Overflow::Scroll, padding: Rect {
        start: Dimension::Points(5.0),
        end: Dimension::Points(5.0),
        top: Dimension::Points(5.0),
        bottom: Dimension::Points(5.0),
    })]
    flex: nwg::FlexboxLayout,

    #[nwg_layout(parent: window, max_column: Some(3), margin: [0, 0, 0, 0], spacing: 0)]
    grid: nwg::GridLayout,

    #[nwg_control(parent: window, focus: true)]
    #[nwg_layout_item(layout: grid, col: 0, row: 0)]
    #[nwg_events(OnTreeItemSelectionChanged: [BasicApp::handle_treeview_select])]
    tree_view: nwg::TreeView,

    #[nwg_control(parent: window)]
    #[nwg_layout_item(layout: flex, margin: Rect{
        start: Dimension::Percent(0.333333333),
        end: Dimension::Points(0.0),
        top: Dimension::Points(0.0),
        bottom: Dimension::Points(0.0),
    })]
    warning_text: nwg::RichLabel,

    #[nwg_control(list_style: nwg::ListViewStyle::Detailed, ex_flags: nwg::ListViewExFlags::from_bits(nwg::ListViewExFlags::HEADER_DRAG_DROP.bits() | nwg::ListViewExFlags::FULL_ROW_SELECT.bits() | nwg::ListViewExFlags::BORDER_SELECT.bits()).unwrap())]
    #[nwg_layout_item(layout: flex, margin: Rect{
        start: Dimension::Percent(0.333333333),
        end: Dimension::Points(0.0),
        top: Dimension::Points(0.0),
        bottom: Dimension::Points(0.0),
    })]
    list_orphan_ace: nwg::ListView,

    #[nwg_control(list_style: nwg::ListViewStyle::Detailed, ex_flags: nwg::ListViewExFlags::from_bits(nwg::ListViewExFlags::HEADER_DRAG_DROP.bits() | nwg::ListViewExFlags::FULL_ROW_SELECT.bits() | nwg::ListViewExFlags::BORDER_SELECT.bits()).unwrap())]
    #[nwg_layout_item(layout: flex, margin: Rect{
        start: Dimension::Percent(0.333333333),
        end: Dimension::Points(0.0),
        top: Dimension::Points(0.0),
        bottom: Dimension::Points(0.0),
    })]
    list_deleg_missing: nwg::ListView,

    #[nwg_control(list_style: nwg::ListViewStyle::Detailed, ex_flags: nwg::ListViewExFlags::from_bits(nwg::ListViewExFlags::HEADER_DRAG_DROP.bits() | nwg::ListViewExFlags::FULL_ROW_SELECT.bits() | nwg::ListViewExFlags::BORDER_SELECT.bits()).unwrap())]
    #[nwg_layout_item(layout: flex, margin: Rect{
        start: Dimension::Percent(0.333333333),
        end: Dimension::Points(0.0),
        top: Dimension::Points(0.0),
        bottom: Dimension::Points(0.0),
    })]
    list_deleg_found: nwg::ListView,
}

impl BasicApp {
    fn init(&self) {
        self.list_orphan_ace.set_headers_enabled(true);
        self.list_orphan_ace.insert_column(nwg::InsertListViewColumn {
            width: Some(100),
            text: Some("Resource".to_owned()),
            ..Default::default()
        });
        self.list_orphan_ace.insert_column(nwg::InsertListViewColumn {
            text: Some("Access rights".to_owned()),
            ..Default::default()
        });
        self.list_deleg_missing.set_headers_enabled(true);
        self.list_deleg_missing.insert_column(nwg::InsertListViewColumn {
            width: Some(100),
            text: Some("Resource".to_owned()),
            ..Default::default()
        });
        self.list_deleg_missing.insert_column(nwg::InsertListViewColumn {
            text: Some("Access rights".to_owned()),
            ..Default::default()
        });
        self.list_deleg_found.set_headers_enabled(true);
        self.list_deleg_found.insert_column(nwg::InsertListViewColumn {
            width: Some(100),
            text: Some("Resource".to_owned()),
            ..Default::default()
        });
        self.list_deleg_found.insert_column(nwg::InsertListViewColumn {
            text: Some("Access rights".to_owned()),
            ..Default::default()
        });
        self.refresh();
    }

    fn about(&self) {
        let p = nwg::MessageParams {
            title: "About ADeleg",
            content: &format!("{}\n\nVersion {}\nDownload the latest version at: {}",
                env!("CARGO_PKG_DESCRIPTION"), env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_REPOSITORY")),
            buttons: nwg::MessageButtons::Ok,
            icons: nwg::MessageIcons::Question
        };
        nwg::message(&p);
    }

    fn online_help(&self) {
        if let Err(e) = std::process::Command::new("cmd.exe")
            .args(&["/c", "start", "", env!("CARGO_PKG_REPOSITORY")])
            .spawn() {
                eprintln!(" [!] {}", e);
        }
    }

    fn set_view_index_by_resources(&self) {
        {
            *(self.view_by_trustee.borrow_mut()) = false;
        }
        self.redraw();
    }

    fn set_view_index_by_trustees(&self) {
        {
            *(self.view_by_trustee.borrow_mut()) = true;
        }
        let results = self.results.as_ref().unwrap().borrow();
        let mut warning_count = 0;
        for (_, result) in results.iter() {
            match result {
                Ok(res) => {
                    if res.non_canonical_ace.is_some() {
                        warning_count += 1;
                    }
                },
                Err(_) => {
                    warning_count += 1;
                },
            }
        }
        if warning_count > 0 {
            BasicApp::show_warning(&format!("{} warnings were generated during analysis, switch back to Resources view to see them", warning_count));
        }
        self.redraw();
    }

    fn location_to_tree_path(&self, location: &DelegationLocation) -> Vec<String> {
        match &location {
            DelegationLocation::Global => vec!["Global".to_owned()],
            DelegationLocation::DefaultSecurityDescriptor(class_name) => vec!["Global".to_owned(), format!("All {} objects", class_name)],
            DelegationLocation::Dn(dn) => {
                // Naming contexts overlap: we need to get the longest matching suffix (DC=DomainDnsZones,DC=example,DC=com
                // and not DC=example,DC=com)
                let engine = self.engine.as_ref().unwrap().borrow();
                let mut longest_match: Option<String> = None;
                for nc in &engine.naming_contexts {
                    if ends_with_case_insensitive(&dn, nc) {
                        if nc.len() > longest_match.as_ref().map(|s| s.len()).unwrap_or(0) {
                            longest_match = Some(nc.to_string());
                        }
                    }
                }
                if let Some(nc) = longest_match {
                    let dn = replace_suffix_case_insensitive(&dn, &nc, "");
                    let mut parts = vec![nc];
                    for part in dn.trim_matches(',').split(',').filter(|s| s.len() > 0).rev() {
                        parts.push(part.to_owned());
                    }
                    return parts;
                }
                vec![dn.to_owned()]
            },
        }
    }

    fn tree_path_to_location(&self, tree_path: &[String]) -> DelegationLocation {
        if tree_path.last().map(|s| s.as_str()) == Some("Global") {
            if let Some(class_name) = tree_path.get(0) {
                if let Some(class_name) = class_name.strip_prefix("All ") {
                    if let Some(class_name) = class_name.strip_suffix(" objects") {
                        return DelegationLocation::DefaultSecurityDescriptor(class_name.to_string())
                    }
                }
                DelegationLocation::Dn("?".to_string())
            } else {
                DelegationLocation::Global
            }
        } else {
            DelegationLocation::Dn(tree_path.join(","))
        }
    }

    fn trustee_to_tree_path(&self, trustee: &Sid) -> Vec<String> {
        let engine = self.engine.as_ref().unwrap().borrow();
        let dn = engine.resolve_sid(trustee);

        // Naming contexts overlap: we need to get the longest matching suffix (DC=DomainDnsZones,DC=example,DC=com
        // and not DC=example,DC=com)
        let mut longest_match: Option<String> = None;
        for nc in &engine.naming_contexts {
            if ends_with_case_insensitive(&dn, nc) {
                if nc.len() > longest_match.as_ref().map(|s| s.len()).unwrap_or(0) {
                    longest_match = Some(nc.to_string());
                }
            }
        }
        if let Some(nc) = longest_match {
            let dn = replace_suffix_case_insensitive(&dn, &nc, "");
            let mut parts = vec![nc];
            for part in dn.trim_matches(',').split(',').filter(|s| s.len() > 0).rev() {
                parts.push(part.to_owned());
            }
            return parts;
        }
        vec!["Global".to_owned(), dn]
    }

    fn tree_path_to_trustee(&self, tree_path: &[String]) -> Sid {
        if tree_path.last().map(|s| s.as_str()) == Some("Global") {
            if let Some(sid) = tree_path.get(0) {
                if let Ok(sid) = Sid::try_from(sid.as_str()) {
                    return sid;
                }
            }
        } else {
            let dn = tree_path.join(",");
            let engine = self.engine.as_ref().unwrap().borrow();
            if let Some(sid) = engine.resolve_str_to_sid(&dn) {
                return sid;
            }
        }
        Sid::try_from("S-1-0-0").unwrap() // NULL SID
    }

    fn refresh(&self) {
        self.tree_view.clear();
        self.handle_treeview_select();

        self.tree_view.insert_item("Loading...", None, nwg::TreeInsert::Root);
        self.tree_view.set_enabled(false);

        {
            let mut results = self.results.as_ref().unwrap().borrow_mut();
            let mut engine = self.engine.as_ref().unwrap().borrow_mut();
            let templates = self.template_file_paths.as_ref().unwrap().borrow();
            let delegations = self.delegation_file_paths.as_ref().unwrap().borrow();

            engine.templates.clear();
            engine.delegations.clear();
            results.clear();

            for file_path in templates.iter() {
                let json = match std::fs::read_to_string(file_path) {
                    Ok(s) => s,
                    Err(e) => {
                        BasicApp::show_error(&format!("Unable to read template file {} : {}", file_path, e));
                        return;
                    },
                };
                if let Err(e) = engine.load_template_json(&json) {
                    BasicApp::show_error(&format!("Unable to parse template file {} : {}", file_path, e));
                    return;
                }
            }
            for file_path in templates.iter() {
                let json = match std::fs::read_to_string(file_path) {
                    Ok(s) => s,
                    Err(e) => {
                        BasicApp::show_error(&format!("Unable to read delegation file {} : {}", file_path, e));
                        return;
                    },
                };
                if let Err(e) = engine.load_delegation_json(&json) {
                    BasicApp::show_error(&format!("Unable to parse delegation file {} : {}", file_path, e));
                    return;
                }
            }

            let new_results = match engine.run() {
                Ok(r) => r,
                Err(e) => {
                    self.tree_view.clear();
                    self.tree_view.insert_item("Error", None, nwg::TreeInsert::Root);
                    HashMap::new()
                },
            };
            results.extend(new_results);
        }
        self.redraw();
    }

    fn show_warning(s: &str) {
        let p = nwg::MessageParams {
            title: "Warning",
            content: s,
            buttons: nwg::MessageButtons::Ok,
            icons: nwg::MessageIcons::Warning
        };
        nwg::message(&p);
    }

    fn show_error(s: &str) {
        let p = nwg::MessageParams {
            title: "Error",
            content: s,
            buttons: nwg::MessageButtons::Ok,
            icons: nwg::MessageIcons::Error
        };
        nwg::message(&p);
    }

    fn redraw(&self) {
        let view_by_trustee = *self.view_by_trustee.borrow();
        self.menu_view_index_by_resources.set_checked(!view_by_trustee);
        self.menu_view_index_by_trustees.set_checked(view_by_trustee);
        self.window.focus();
        self.tree_view.clear();
        let results = self.results.as_ref().unwrap().borrow();

        if view_by_trustee {
            let mut trustees: HashSet<Sid> = HashSet::new();
            for (location, res) in results.iter() {
                if let Ok(res) = res {
                    for ace in &res.orphan_aces {
                        trustees.insert(ace.trustee.clone());
                    }
                    for (_, trustee) in &res.delegations_missing {
                        trustees.insert(trustee.clone());
                    }
                    for (_, trustee, _) in &res.delegations_found {
                        trustees.insert(trustee.clone());
                    }
                }
            }
            for trustee in &trustees {
                let mut parent = None;
                let mut cursor = self.tree_view.root();
                let path = self.trustee_to_tree_path(&trustee);
                for part in &path {
                    loop {
                        match cursor.take() {
                            Some(node) => {
                                if let Some(txt) = self.tree_view.item_text(&node) {
                                    if &txt == part {
                                        cursor = self.tree_view.first_child(&node);
                                        parent = Some(node);
                                        break;
                                    }
                                }
                                cursor = self.tree_view.next_sibling(&node);
                            },
                            None => {
                                let node = self.tree_view.insert_item(part, parent.as_ref(), nwg::TreeInsert::Last);
                                cursor = self.tree_view.first_child(&node);
                                parent = Some(node);
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            let mut results: Vec<(&DelegationLocation, &Result<AdelegResult, AdelegError>)> = results.iter().collect();
            results.sort_by(|(loc_a, _), (loc_b, _)| loc_a.cmp(loc_b));
            for (location, res) in results {
                let mut parent = None;
                let mut cursor = self.tree_view.root();
                let path = self.location_to_tree_path(&location);
                for part in &path {
                    loop {
                        match cursor.take() {
                            Some(node) => {
                                if let Some(txt) = self.tree_view.item_text(&node) {
                                    if &txt == part {
                                        cursor = self.tree_view.first_child(&node);
                                        parent = Some(node);
                                        break;
                                    }
                                }
                                cursor = self.tree_view.next_sibling(&node);
                            },
                            None => {
                                let node = self.tree_view.insert_item(part, parent.as_ref(), nwg::TreeInsert::Last);
                                cursor = self.tree_view.first_child(&node);
                                parent = Some(node);
                                break;
                            }
                        }
                    }
                }
            }
        }
        self.tree_view.set_enabled(true);
        self.flex.fit().expect("flexbox layout fit error");
    }

    fn show_template_load_dialog(&self) {
        let mut dialog = nwg::FileDialog::default();
        nwg::FileDialog::builder()
            .title("Load templates")
            .action(nwg::FileDialogAction::Open)
            .multiselect(true)
            .filters("JSON Template(*.json)|Any(*)")
            .build(&mut dialog)
            .expect("unable to build file dialog");
        let chosen = dialog.run(Some(&self.window));
        if !chosen {
            return;
        }

        let mut files: Vec<String> = dialog.get_selected_items()
            .expect("unable to fetch selected files")
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        self.template_file_paths.as_ref().unwrap().borrow_mut().append(&mut files);
    }

    fn show_delegation_load_dialog(&self) {
        let mut dialog = nwg::FileDialog::default();
        nwg::FileDialog::builder()
            .title("Load delegations")
            .action(nwg::FileDialogAction::Open)
            .multiselect(true)
            .filters("JSON Delegation(*.json)|Any(*)")
            .build(&mut dialog)
            .expect("unable to build file dialog");
        let chosen = dialog.run(Some(&self.window));
        if !chosen {
            return;
        }

        let mut files: Vec<String> = dialog.get_selected_items()
            .expect("unable to fetch selected files")
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        self.delegation_file_paths.as_ref().unwrap().borrow_mut().append(&mut files);
        self.refresh();
    }

    fn handle_treeview_select(&self) {
        self.warning_text.set_text("");
        self.list_orphan_ace.clear();
        self.list_deleg_missing.clear();
        self.list_deleg_found.clear();

        let mut path = vec![];
        let mut node = self.tree_view.selected_item();
        if node.is_none() {
            return;
        }
        while let Some(item) = node {
            match self.tree_view.item_text(&item) {
                Some(txt) => path.push(txt),
                None => return,
            }
            node = self.tree_view.parent(&item);
        }

        let view_by_trustees = *self.view_by_trustee.borrow();
        let results = self.results.as_ref().unwrap().borrow();
        let engine = self.engine.as_ref().unwrap().borrow();

        if view_by_trustees {
            let trustee = self.tree_path_to_trustee(&path);
            for (location, result) in results.iter() {
                if let Ok(result) = result {
                    for ace in &result.orphan_aces {
                        if &ace.trustee != &trustee {
                            continue;
                        }
                        self.list_orphan_ace.insert_item(nwg::InsertListViewItem {
                            index: Some(0),
                            column_index: 0,
                            text: Some(location.to_string()),
                            image: None,
                        });
                        self.list_orphan_ace.insert_item(nwg::InsertListViewItem {
                            index: Some(0),
                            column_index: 2,
                            text: Some(engine.describe_ace(
                                ace.access_mask,
                                ace.get_object_type(),
                                ace.get_inherited_object_type(),
                                ace.get_container_inherit(),
                                ace.get_inherit_only()
                            )),
                            image: None,
                        });
                    }
                    for (delegation, deleg_trustee) in &result.delegations_missing {
                        if deleg_trustee != &trustee {
                            continue;
                        }
                        self.list_deleg_missing.insert_item(nwg::InsertListViewItem {
                            index: Some(0),
                            column_index: 0,
                            text: Some(location.to_string()),
                            image: None,
                        });
                        self.list_orphan_ace.insert_item(nwg::InsertListViewItem {
                            index: Some(0),
                            column_index: 1,
                            text: Some(engine.describe_delegation_rights(&delegation.rights)),
                            image: None,
                        });
                    }
                    for (delegation, deleg_trustee, _) in &result.delegations_found {
                        if deleg_trustee != &trustee {
                            continue;
                        }
                        self.list_deleg_found.insert_item(nwg::InsertListViewItem {
                            index: Some(0),
                            column_index: 0,
                            text: Some(location.to_string()),
                            image: None,
                        });
                        self.list_deleg_found.insert_item(nwg::InsertListViewItem {
                            index: Some(0),
                            column_index: 1,
                            text: Some(engine.describe_delegation_rights(&delegation.rights)),
                            image: None,
                        });
                    }
                }
            }
        } else {
            let location = self.tree_path_to_location(&path);
            if let Some(result) = results.get(&location) {
                let result = match result {
                    Ok(res) => res,
                    Err(e) => {
                        self.warning_text.set_text(&e.to_string());
                        return;
                    },
                };
    
                for ace in &result.orphan_aces {
                    self.list_orphan_ace.insert_item(nwg::InsertListViewItem {
                        index: Some(0),
                        column_index: 0,
                        text: Some(engine.resolve_sid(&ace.trustee)),
                        image: None,
                    });
                    self.list_orphan_ace.insert_item(nwg::InsertListViewItem {
                        index: Some(0),
                        column_index: 1,
                        text: Some(engine.resolve_sid(&ace.trustee)),
                        image: None,
                    });
                    self.list_orphan_ace.insert_item(nwg::InsertListViewItem {
                        index: Some(0),
                        column_index: 2,
                        text: Some(engine.describe_ace(
                            ace.access_mask,
                            ace.get_object_type(),
                            ace.get_inherited_object_type(),
                            ace.get_container_inherit(),
                            ace.get_inherit_only()
                        )),
                    image: None,
                    });
                }
                for (delegation, trustee) in &result.delegations_missing {
                    self.list_deleg_missing.insert_item(nwg::InsertListViewItem {
                        index: Some(0),
                        column_index: 0,
                        text: Some(engine.resolve_sid(&trustee)),
                        image: None,
                    });
                    self.list_orphan_ace.insert_item(nwg::InsertListViewItem {
                        index: Some(0),
                        column_index: 1,
                        text: Some(engine.describe_delegation_rights(&delegation.rights)),
                        image: None,
                    });
                }
                for (delegation, trustee, _) in &result.delegations_found {
                    self.list_deleg_found.insert_item(nwg::InsertListViewItem {
                        index: Some(0),
                        column_index: 0,
                        text: Some(engine.resolve_sid(&trustee)),
                        image: None,
                    });
                    self.list_deleg_found.insert_item(nwg::InsertListViewItem {
                        index: Some(0),
                        column_index: 1,
                        text: Some(engine.describe_delegation_rights(&delegation.rights)),
                        image: None,
                    });
                }
            }
        }
    }

    fn cleanup(&self) {
        nwg::stop_thread_dispatch();
    }
}

pub(crate) fn run_gui() {
    nwg::init().expect("Failed to init Native Windows GUI");
    let mut default_font = nwg::Font::default();
    if nwg::Font::builder().family("Segoe UI").size(15).build(&mut default_font).is_ok() {
        nwg::Font::set_global_default(Some(default_font));
    }

    let _dialog = ConnectionDialog::build_ui(Default::default()).expect("Failed to build UI");
    nwg::dispatch_thread_events();
    std::process::exit(0);
}

#[derive(Default, NwgUi)]
pub struct ConnectionDialog {
    #[nwg_control(size: (500, 290), center: true, title: "ADeleg | LDAP Connection", flags: "WINDOW|VISIBLE")]
    #[nwg_events(
        OnInit: [ConnectionDialog::init],
        OnWindowClose: [ConnectionDialog::close],
    )]
    window: nwg::Window,

    #[nwg_layout(parent: window, spacing: 1)]
    grid: nwg::GridLayout,

    #[nwg_control(text: "Use the same domain controller as this host", flags: "VISIBLE|GROUP")]
    #[nwg_layout_item(layout: grid, row: 0, col: 0)]
    #[nwg_events(OnButtonClick: [ConnectionDialog::handle_switch_mode])]
    choice_dclocator: nwg::RadioButton,

    #[nwg_control(text: "Use a specific domain controller")]
    #[nwg_layout_item(layout: grid, row: 1, col: 0)]
    #[nwg_events(OnButtonClick: [ConnectionDialog::handle_switch_mode])]
    choice_explicit: nwg::RadioButton,

    #[nwg_control(placeholder_text: Some("Hostname (dc.hostname.example.com)"), text: "192.168.58.10")]
    #[nwg_layout_item(layout: grid, row: 2, col: 0)]
    dc_hostname: nwg::TextInput,

    #[nwg_control(placeholder_text: Some("Port (default is 389)"), limit: 5)]
    #[nwg_layout_item(layout: grid, row: 3, col: 0)]
    dc_port: nwg::TextInput,

    #[nwg_control(placeholder_text: Some("Domain name"), text: "EXAMPLE")]
    #[nwg_layout_item(layout: grid, row: 4, col: 0)]
    domain: nwg::TextInput,

    #[nwg_control(placeholder_text: Some("Username"), text: "noright")]
    #[nwg_layout_item(layout: grid, row: 5, col: 0)]
    username: nwg::TextInput,

    #[nwg_control(placeholder_text: Some("Password"), password: Some('*'), text: "Bonjour1!")]
    #[nwg_layout_item(layout: grid, row: 6, col: 0)]
    password: nwg::TextInput,

    #[nwg_control(text: "Connect")]
    #[nwg_events(OnButtonClick: [ConnectionDialog::handle_connect])]
    #[nwg_layout_item(layout: grid, row: 7, col: 0)]
    connect_btn: nwg::Button,
}

impl ConnectionDialog {
    fn init(&self) {
        self.choice_dclocator.set_check_state(nwg::RadioButtonState::Checked);
        self.handle_switch_mode();
        self.connect_btn.focus();
    }

    fn handle_switch_mode(&self) {
        let explicit = self.choice_explicit.check_state() == nwg::RadioButtonState::Checked;
        self.dc_hostname.set_enabled(explicit);
        self.dc_port.set_enabled(explicit);
        self.domain.set_enabled(explicit);
        self.username.set_enabled(explicit);
        self.password.set_enabled(explicit);
    }

    fn handle_connect(&self) {
        let explicit = self.choice_explicit.check_state() == nwg::RadioButtonState::Checked;
        let dc_hostname = self.dc_hostname.text();
        let domain = self.domain.text();
        let username = self.username.text();
        let password = self.password.text();
        let dc_port: u16 = self.dc_port.text().trim().parse().unwrap_or(389);

        let (server, credentials) = if explicit {
            if domain.is_empty() && username.is_empty() {
                (Some(dc_hostname), None)
            } else {
                if domain.is_empty() || username.is_empty() {
                    BasicApp::show_error("Invalid parameters: when specifying an explicit username or domain, both must be specified");
                    return;
                }
                (Some(dc_hostname), Some(LdapCredentials {
                    domain: &domain,
                    username: &username,
                    password: &password,
                }))
            }
        } else {
            (None , None)
        };

        let ldap = match LdapConnection::new(server.as_deref(), dc_port, credentials.as_ref()) {
            Ok(conn) => conn,
            Err(e) => {
                BasicApp::show_error(&format!("Unable to connect: {}", e));
                return;
            }
        };

        self.window.set_visible(false);
        let mut engine = RefCell::new(Engine::new(Box::leak(Box::new(ldap)), true));
        if let Err(e) = engine.borrow_mut().load_delegation_json(BUILTIN_ACES) {
            BasicApp::show_error(&format!("Unable to parse builtin delegations: {}", e));
            std::process::exit(1);
        }
        let results = RefCell::new(HashMap::new());
        let _app = BasicApp::build_ui(BasicApp { engine: Some(engine), results: Some(results), ..Default::default() }).expect("Failed to build UI");
        nwg::dispatch_thread_events();
        self.window.close();
    }

    fn close(&self) {
        nwg::stop_thread_dispatch();
    }
}