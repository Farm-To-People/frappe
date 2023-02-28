frappe.ui.form.on("Email Domain", {
	onload: function (frm) {
		if (!frm.doc.__islocal) {
			frm.dashboard.clear_headline();
			let msg = __(
				"Changing any setting will reflect on all the email accounts associated with this domain."
			);
			frm.dashboard.set_headline_alert(msg);
		} else {
			if (!frm.doc.attachment_limit) {
				frappe.call({
					method: "frappe.core.api.file.get_max_file_size",
					callback: function (r) {
						if (!r.exc) {
							frm.set_value("attachment_limit", Number(r.message) / (1024 * 1024));
						}
					},
				});
			}
		}
	},

	email_id:function(frm) {
		frm.set_value("domain_name",frm.doc.email_id.split("@")[1])
	},

	refresh:function(frm){
		// Farm To People, Datahenge
		frm.add_custom_button(__("Validate Email Settings"), () => {
			validate_domain(cur_frm, cur_frm.doc);
		});
	}

});

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


