extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use std::collections::HashMap;
use std::{cell::RefCell, borrow::Borrow};
use std::rc::Rc;
use nwg::{NativeUi, FontBuilder, ProgressBarFlags, TreeItem};
use nwd::NwgUi;
use winldap::connection::{LdapCredentials, LdapConnection};
use authz::{Ace, Sid};
use crate::delegations::{DelegationLocation, Delegation};
use crate::engine::Engine;
use crate::utils::{ends_with_case_insensitive, replace_suffix_case_insensitive};

#[derive(Default, NwgUi)]
pub struct BasicApp {
    engine: Option<RefCell<Engine<'static>>>,
    results: Option<RefCell<HashMap<Sid, HashMap<DelegationLocation, (Vec<Delegation>, Vec<Delegation>, Vec<Ace>)>>>>,

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

    #[nwg_control(parent: menu_file, text: "Re-scan")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::refresh] )]
    menu_item_rescan: nwg::MenuItem,

    #[nwg_control(parent: menu_file, text: "Exit")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::cleanup] )]
    menu_item_exit: nwg::MenuItem,

    #[nwg_control(parent: window, text: "Help")]
    menu_help: nwg::Menu,

    #[nwg_control(parent: menu_help, text: "About...")]
    menu_help_about: nwg::Menu,

    #[nwg_layout(parent: window, spacing: 1)]
    grid: nwg::GridLayout,

    #[nwg_control(parent: window, focus: true)]
    #[nwg_layout_item(layout: grid, row: 0, col: 0, row_span: 3)]
    #[nwg_events(OnTreeItemSelectionChanged: [BasicApp::handle_treeview_select])]
    tree_view: nwg::TreeView,

    #[nwg_control(parent: window, ex_flags: nwg::ListViewExFlags::from_bits(nwg::ListViewExFlags::HEADER_DRAG_DROP.bits() | nwg::ListViewExFlags::FULL_ROW_SELECT.bits() | nwg::ListViewExFlags::BORDER_SELECT.bits()).unwrap())]
    #[nwg_layout_item(layout: grid, col: 1, row: 0, col_span: 2)]
    orphan_aces: nwg::ListView,

    #[nwg_control(parent: window, ex_flags: nwg::ListViewExFlags::from_bits(nwg::ListViewExFlags::HEADER_DRAG_DROP.bits() | nwg::ListViewExFlags::FULL_ROW_SELECT.bits() | nwg::ListViewExFlags::BORDER_SELECT.bits()).unwrap())]
    #[nwg_layout_item(layout: grid, col: 1, row: 1, col_span: 2)]
    delegs_missing: nwg::ListView,

    #[nwg_control(parent: window, ex_flags: nwg::ListViewExFlags::from_bits(nwg::ListViewExFlags::HEADER_DRAG_DROP.bits() | nwg::ListViewExFlags::FULL_ROW_SELECT.bits() | nwg::ListViewExFlags::BORDER_SELECT.bits()).unwrap())]
    #[nwg_layout_item(layout: grid, col: 1, row: 2, col_span: 2)]
    delegs_found: nwg::ListView,
}

impl BasicApp {
    fn init(&self) {
        self.orphan_aces.set_headers_enabled(true);
        self.orphan_aces.set_list_style(nwg::ListViewStyle::Detailed);
        self.orphan_aces.insert_column(nwg::InsertListViewColumn {
            width: Some(200),
            text: Some("Resource".to_owned()),
            ..Default::default()
        });
        self.orphan_aces.insert_column(nwg::InsertListViewColumn {
            text: Some("Access rights".to_owned()),
            ..Default::default()
        });
        self.delegs_missing.insert_column("DN");
        self.delegs_missing.set_headers_enabled(true);
        self.delegs_missing.set_list_style(nwg::ListViewStyle::Detailed);
        self.delegs_found.insert_column("DN");
        self.delegs_found.set_headers_enabled(true);
        self.delegs_found.set_list_style(nwg::ListViewStyle::Detailed);

        self.refresh();
    }

    fn refresh(&self) {
        self.window.focus();
        self.tree_view.clear();
        self.orphan_aces.clear();
        self.delegs_missing.clear();
        self.delegs_found.clear();

        self.tree_view.insert_item("Loading...", None, nwg::TreeInsert::Root);
        self.tree_view.set_enabled(false);

        let engine = self.engine.as_ref().unwrap().borrow();
        let mut results = self.results.as_ref().unwrap().borrow_mut();
        results.clear();
        results.extend(engine.run());

        self.tree_view.clear();
        for (trustee, _) in results.iter() {
            let trustee = self.engine.as_ref().unwrap().borrow().resolve_sid(trustee);
            let parts = self.engine.as_ref().unwrap().borrow().split_trustee_components(&trustee);
            let mut parent = None;
            let mut cursor = self.tree_view.root();
            for part in &parts {
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
        self.tree_view.set_enabled(true);
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

        let before = self.engine.as_ref().unwrap().borrow().templates.len();
        let files = dialog.get_selected_items().expect("unable to fetch selected files");
        for path in files {
            if let Err(e) = self.engine.as_ref().unwrap().borrow_mut().register_template(&path.to_string_lossy()) {
                let p = nwg::MessageParams {
                    title: "Error",
                    content: &format!("Unable to load template file: {}", e),
                    buttons: nwg::MessageButtons::Ok,
                    icons: nwg::MessageIcons::Warning
                };
                nwg::message(&p);
                return;
            }
        }
        let after = self.engine.as_ref().unwrap().borrow().templates.len();

        let p = nwg::MessageParams {
            title: "Success",
            content: &format!("{} templates loaded", after - before),
            buttons: nwg::MessageButtons::Ok,
            icons: nwg::MessageIcons::Info,
        };
        nwg::message(&p);
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

        let before = self.engine.as_ref().unwrap().borrow().delegations.len();
        let files = dialog.get_selected_items().expect("unable to fetch selected files");
        for path in files {
            if let Err(e) = self.engine.as_ref().unwrap().borrow_mut().register_delegation(&path.to_string_lossy()) {
                let p = nwg::MessageParams {
                    title: "Error",
                    content: &format!("Unable to load delegation file: {}", e),
                    buttons: nwg::MessageButtons::Ok,
                    icons: nwg::MessageIcons::Warning
                };
                nwg::message(&p);
                return;
            }
        }
        let after = self.engine.as_ref().unwrap().borrow().delegations.len();

        let p = nwg::MessageParams {
            title: "Success",
            content: &format!("{} delegations loaded", after - before),
            buttons: nwg::MessageButtons::Ok,
            icons: nwg::MessageIcons::Info,
        };
        nwg::message(&p);
    }

    fn handle_treeview_select(&self) {
        self.orphan_aces.clear();
        self.delegs_missing.clear();
        self.delegs_found.clear();
        self.orphan_aces.set_headers_enabled(true);
        self.orphan_aces.set_list_style(nwg::ListViewStyle::Detailed);

        let mut selected_dn = String::new();
        let mut node = self.tree_view.selected_item();
        while let Some(item) = node {
            match self.tree_view.item_text(&item) {
                Some(txt) => {
                    if selected_dn.is_empty() {
                        selected_dn = txt;
                    } else {
                        selected_dn = format!("{},{}", selected_dn, txt);
                    }
                },
                None => return,
            }
            node = self.tree_view.parent(&item);
        }
        if let Some(sid) = self.engine.as_ref().unwrap().borrow().resolve_str_to_sid(&selected_dn) {
            let results = self.results.as_ref().unwrap().borrow();
            let engine = self.engine.as_ref().unwrap().borrow();
            if let Some(locations) = results.get(&sid) {
                for (location, (deleg_found, deleg_missing, orphan_aces)) in locations {
                    for ace in orphan_aces {
                        let pretty_location = match location {
                            DelegationLocation::DefaultSecurityDescriptor(c) => format!("All objects of class {}", c),
                            DelegationLocation::Dn(d) => d.to_owned(),
                            DelegationLocation::Global => format!("Global"),
                        };
                        self.orphan_aces.insert_item(nwg::InsertListViewItem {
                            index: Some(0),
                            column_index: 0,
                            text: Some(pretty_location),
                            image: None,
                        });
                        self.orphan_aces.insert_item(nwg::InsertListViewItem {
                            index: Some(0),
                            column_index: 1,
                            text: Some(engine.describe_ace(ace)),
                            image: None,
                        });
                    }
                    for delegation in deleg_missing {
                        self.delegs_missing.insert_item(format!("{:?} {:?}", location, delegation));
                    }
                    for delegation in deleg_found {
                        self.delegs_found.insert_item(format!("{:?} {:?}", location, delegation));
                    }
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
                    let p = nwg::MessageParams {
                        title: "Invalid parameters",
                        content: "When specifying an explicit username or domain, both must be specified",
                        buttons: nwg::MessageButtons::Ok,
                        icons: nwg::MessageIcons::Warning
                    };
                    nwg::message(&p);
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
                let p = nwg::MessageParams {
                    title: "Connection error",
                    content: &format!("Unable to connect: {}", e),
                    buttons: nwg::MessageButtons::Ok,
                    icons: nwg::MessageIcons::Warning
                };
                nwg::message(&p);
                return;
            }
        };

        self.window.set_visible(false);
        let engine = RefCell::new(Engine::new(Box::leak(Box::new(ldap))));
        let results = RefCell::new(HashMap::new());
        let _app = BasicApp::build_ui(BasicApp { engine: Some(engine), results: Some(results), ..Default::default() }).expect("Failed to build UI");
        nwg::dispatch_thread_events();
        self.window.close();
    }

    fn close(&self) {
        nwg::stop_thread_dispatch();
    }
}