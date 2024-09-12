frappe.listview_settings["Email Account"] = {
	add_fields: ["default_incoming", "default_outgoing", "enable_incoming", "enable_outgoing"],
	get_indicator: function (doc) {
		if (doc.default_incoming && doc.default_outgoing) {
			var color = doc.enable_incoming && doc.enable_outgoing ? "blue" : "gray";
			return [
				__("Default Sending and Inbox"),
				color,
				"default_incoming,=,Yes|default_outgoing,=,Yes",
			];
		} else if (doc.default_incoming) {
			color = doc.enable_incoming ? "blue" : "gray";
			return [__("Default Inbox"), color, "default_incoming,=,Yes"];
		} else if (doc.default_outgoing) {
			color = doc.enable_outgoing ? "blue" : "gray";
			return [__("Default Sending"), color, "default_outgoing,=,Yes"];
		/* Datahenge: This previously said 'Inbox', which is wrong.  
						You can create an Account, outbound only, and that doesn't make it an Inbox.
						Change to just say 'Other'
		*/
		} else {
			color = doc.enable_incoming ? "blue" : "gray";
			return [__("Other"), color, "default_outgoing,=,No|default_incoming=No"];
		}
	},
};

frappe.help.youtube_id["Email Account"] = "YFYe0DrB95o";
