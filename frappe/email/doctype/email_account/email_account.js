frappe.email_defaults = {
	"GMail": {
		"email_server": "imap.gmail.com",
		"use_ssl": 1,
		"enable_outgoing": 1,
		"smtp_server": "smtp.gmail.com",
		"smtp_port": 587,
		"use_tls": 1,
		"use_imap": 1
	},
	"Outlook.com": {
		"email_server": "imap-mail.outlook.com",
		"use_ssl": 1,
		"enable_outgoing": 1,
		"smtp_server": "smtp-mail.outlook.com",
		"smtp_port": 587,
		"use_tls": 1,
		"use_imap": 1
	},
	"Sendgrid": {
		"enable_outgoing": 1,
		"smtp_server": "smtp.sendgrid.net",
		"smtp_port": 587,
		"use_tls": 1,
	},
	"SparkPost": {
		"enable_incoming": 0,
		"enable_outgoing": 1,
		"smtp_server": "smtp.sparkpostmail.com",
		"smtp_port": 587,
		"use_tls": 1
	},
	"Yahoo Mail": {
		"email_server": "imap.mail.yahoo.com",
		"use_ssl": 1,
		"enable_outgoing": 1,
		"smtp_server": "smtp.mail.yahoo.com",
		"smtp_port": 587,
		"use_tls": 1,
		"use_imap": 1
	},
	"Yandex.Mail": {
		"email_server": "imap.yandex.com",
		"use_ssl": 1,
		"enable_outgoing": 1,
		"smtp_server": "smtp.yandex.com",
		"smtp_port": 587,
		"use_tls": 1,
		"use_imap": 1
	},
};

frappe.email_defaults_pop = {
	"GMail": {
		"email_server": "pop.gmail.com"
	},
	"Outlook.com": {
		"email_server": "pop3-mail.outlook.com"
	},
	"Yahoo Mail": {
		"email_server": "pop.mail.yahoo.com"
	},
	"Yandex.Mail": {
		"email_server": "pop.yandex.com"
	},

};

frappe.ui.form.on("Email Account", {
	service: function(frm) {
		$.each(frappe.email_defaults[frm.doc.service], function(key, value) {
			frm.set_value(key, value);
		});
		if (!frm.doc.use_imap) {
			$.each(frappe.email_defaults_pop[frm.doc.service], function(key, value) {
				frm.set_value(key, value);
			});
		}
		frm.events.show_gmail_message_for_less_secure_apps(frm);
	},

	use_imap: function(frm) {
		if (!frm.doc.use_imap) {
			$.each(frappe.email_defaults_pop[frm.doc.service], function(key, value) {
				frm.set_value(key, value);
			});
		}
		else{
			$.each(frappe.email_defaults[frm.doc.service], function(key, value) {
				frm.set_value(key, value);
			});
		}
	},

	enable_incoming: function(frm) {
		frm.doc.no_remaining = null; //perform full sync
		//frm.set_df_property("append_to", "reqd", frm.doc.enable_incoming);
		frm.trigger("warn_autoreply_on_incoming");
	},

	enable_auto_reply: function(frm) {
		frm.trigger("warn_autoreply_on_incoming");
	},

	notify_if_unreplied: function(frm) {
		frm.set_df_property("send_notification_to", "reqd", frm.doc.notify_if_unreplied);
	},

	onload: function(frm) {
		frm.set_df_property("append_to", "only_select", true);
		frm.set_query("append_to", "frappe.email.doctype.email_account.email_account.get_append_to");
	},

	refresh: function(frm) {
		frm.events.set_domain_fields(frm);
		frm.events.enable_incoming(frm);
		frm.events.notify_if_unreplied(frm);
		frm.events.show_gmail_message_for_less_secure_apps(frm);

		if(frappe.route_flags.delete_user_from_locals && frappe.route_flags.linked_user) {
			delete frappe.route_flags.delete_user_from_locals;
			delete locals['User'][frappe.route_flags.linked_user];
		}

		// Datahenge: Begin
		frm.add_custom_button(__('Send Test Email'), function() {
			send_test_email(frm);
		});
		// Datahenge: End

	},

	show_gmail_message_for_less_secure_apps: function(frm) {
		frm.dashboard.clear_headline();
		if(frm.doc.service==="GMail") {
			frm.dashboard.set_headline_alert('Gmail will only work if you allow access for less secure \
				apps in Gmail settings. <a target="_blank" \
				href="https://support.google.com/accounts/answer/6010255?hl=en">Read this for details</a>');
		}
	},

	email_id:function(frm) {
		//pull domain and if no matching domain go create one
		frm.events.update_domain(frm);
	},

	update_domain: function(frm){
		if (!frm.doc.email_id && !frm.doc.service){
			return;
		}

		frappe.call({
			method: 'get_domain',
			doc: frm.doc,
			args: {
				"email_id": frm.doc.email_id
			},
			callback: function (r) {
				if (r.message) {
					frm.events.set_domain_fields(frm, r.message);
				} else {
					frm.set_value("domain", "");
					frappe.confirm(__('Email Domain not configured for this account, Create one?'),
						function () {
							frappe.model.with_doctype("Email Domain", function() {
								frappe.route_options = { email_id: frm.doc.email_id };
								frappe.route_flags.return_to_email_account = 1;
								var doc = frappe.model.get_new_doc("Email Domain");
								frappe.set_route("Form", "Email Domain", doc.name);
							});
						}
					);
				}
			}
		});
	},

	set_domain_fields: function(frm, args) {
		if(!args){
			args = frappe.route_flags.set_domain_values? frappe.route_options: {};
		}

		for(var field in args) {
			frm.set_value(field, args[field]);
		}

		delete frappe.route_flags.set_domain_values;
		frappe.route_options = {};
	},

	email_sync_option: function(frm) {
		// confirm if the ALL sync option is selected

		if(frm.doc.email_sync_option == "ALL"){
			var msg = __("You are selecting Sync Option as ALL, It will resync all \
				read as well as unread message from server. This may also cause the duplication\
				of Communication (emails).");
			frappe.confirm(msg, null, function() {
				frm.set_value("email_sync_option", "UNSEEN");
			});
		}
	},

	warn_autoreply_on_incoming: function(frm) {
		if (frm.doc.enable_incoming && frm.doc.enable_auto_reply && frm.doc.__islocal) {
			var msg = __("Enabling auto reply on an incoming email account will send automated replies \
				to all the synchronized emails. Do you wish to continue?");
			frappe.confirm(msg, null, function() {
				frm.set_value("enable_auto_reply", 0);
				frappe.show_alert({message: __("Disabled Auto Reply"), indicator: "blue"});
			});
		}
	}
});



function send_test_email(frm) {

	let me = this;

	const title = __("Test Email Account by Sending a Message");
	const fields = [
		{
			fieldname: 'recipients',
			fieldtype:'Data',
			label: __('Recipients:'),
			reqd: 1
		}
	];

	var this_dialog = new frappe.ui.Dialog({
		title: title,
		fields: fields
	});

	this_dialog.set_primary_action(__('Update'), function() {
		const dialog_data = this_dialog.get_values();
		frappe.call({
			method:"frappe.core.doctype.communication.email.make",
			args: {
				recipients: dialog_data.recipients,
				subject: "Test Email from ERPNext",
				content: "This is a Test Email from " + frm.doc.name,
				send_email: 1,
				print_html: 1,
				send_me_a_copy: 0,
				sender: frm.doc.email_id,
				read_receipt: 0,
			},
			callback(r) {
				if (!r.exc) {
					frappe.utils.play_sound("email");

					if (r.message["emails_not_sent_to"]) {
						frappe.msgprint(__("Email not sent to {0} (unsubscribed / disabled)",
							[ frappe.utils.escape_html(r.message["emails_not_sent_to"]) ]) );
					}
				} else {
					console.log(r);
					frappe.msgprint(__("There were errors while sending email. Please try again."));
					// try the error callback if it exists
					if (r.error) {
						console.log(e); // eslint-disable-line
					}
				}
			} //end of callback block
		});
		this_dialog.hide();
		/*
		frappe.call({
			'method': 'ftp.ftp_api.api.update_customer_emailid',
			'args': {
				'current_email_id': frm.doc.email_id,
				'new_email_id': dialog_data.new_email_address,
			},
			'callback': (r) => {
				frm.reload_doc();
				frappe.msgprint("Email address updated.")
			}
		});
		this_dialog.hide();
		*/

	});
	this_dialog.show();
}
