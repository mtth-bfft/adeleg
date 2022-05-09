extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use std::{cell::RefCell, borrow::Borrow};
use std::rc::Rc;
use nwg::{NativeUi, FontBuilder};
use nwd::NwgUi;
use winldap::connection::{LdapCredentials, LdapConnection};

#[derive(Default, NwgUi)]
pub struct BasicApp {
    ldap: Option<LdapConnection>,

    #[nwg_control(maximized: true, title: "ADeleg", flags: "MAIN_WINDOW|VISIBLE")]
    #[nwg_events(
        OnWindowClose: [BasicApp::cleanup],
        OnInit: [BasicApp::refresh],
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
    menu_item_load_delegations: nwg::MenuItem,

    #[nwg_control(parent: menu_file, text: "Exit")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::cleanup] )]
    menu_item_exit: nwg::MenuItem,

    #[nwg_control(parent: window, text: "Refresh")]
    #[nwg_events( OnMenuItemSelected: [BasicApp::refresh] )]
    menu_refresh: nwg::Menu,

    #[nwg_control(parent: window, text: "About")]
    menu_about: nwg::Menu,

    #[nwg_layout(parent: window, spacing: 1)]
    grid: nwg::GridLayout,

    #[nwg_control(parent: window, focus: true)]
    #[nwg_layout_item(layout: grid, row: 0, col: 0)]
    tree_view: nwg::TreeView,

    #[nwg_control(text: "Say my name")]
    #[nwg_layout_item(layout: grid, col: 1, row: 0, col_span: 2)]
    hello_button: nwg::Button
}

impl BasicApp {
    fn refresh(&self) {
        self.window.focus();
        self.tree_view.clear();

        self.tree_view.insert_item("DC=example,DC=com", None, nwg::TreeInsert::Root);
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

        let files = dialog.get_selected_items().expect("unable to fetch selected files");
        for path in files {

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
        let _app = BasicApp::build_ui(BasicApp { ..Default::default() }).expect("Failed to build UI");
        nwg::dispatch_thread_events();
        self.window.close();
    }

    fn close(&self) {
        nwg::stop_thread_dispatch();
    }
}
