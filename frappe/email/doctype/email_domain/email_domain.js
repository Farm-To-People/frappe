
frappe.ui.form.on("Email Domain", {
	email_id:function(frm){
		frm.set_value("domain_name",frm.doc.email_id.split("@")[1])
	},

	refresh:function(frm){

		// Farm To People, Datahenge
		frm.add_custom_button(__("Validate Email Settings"), () => {
			validate_domain(cur_frm, cur_frm.doc);
		});
		// EOM

		if (frm.doc.email_id){
			frm.set_value("domain_name",frm.doc.email_id.split("@")[1])
		}

		if (frm.doc.__islocal != 1 && frappe.route_flags.return_to_email_account) {
			var route = frappe.get_prev_route();
			delete frappe.route_flags.return_to_email_account;
			frappe.route_flags.set_domain_values = true

			frappe.route_options = {
				domain: frm.doc.name,
				use_imap: frm.doc.use_imap,
				email_server: frm.doc.email_server,
				use_ssl: frm.doc.use_ssl,
				smtp_server: frm.doc.smtp_server,
				use_tls: frm.doc.use_tls,
				smtp_port: frm.doc.smtp_port
			},
			frappe.set_route(route);
		}
	}
})

function validate_domain (caller_frm, doc) {
	// Validate the email domain's settings:
	frappe.call({
		method: 'frappe.email.doctype.email_domain.email_domain.validate_domain',
		args: { 'email_domain_name': doc.name },
		callback: function(r) {
            if (r.message) {
				frappe.msgprint(__(r.message));
				caller_frm.reload_doc();
			}
		}
    });
}