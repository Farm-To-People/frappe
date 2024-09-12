# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE

import frappe

# select doctypes that are accessed by the user (not read_only) first, so that the
# the validation message shows the user-facing doctype first.
# For example Journal Entry should be validated before GL Entry (which is an internal doctype)

dynamic_link_queries = [
	"""select `tabDocField`.parent,
		`tabDocType`.read_only, `tabDocType`.in_create,
		`tabDocField`.fieldname, `tabDocField`.options
	from `tabDocField`, `tabDocType`
	where `tabDocField`.fieldtype='Dynamic Link' and
	`tabDocType`.`name`=`tabDocField`.parent and `tabDocType`.is_virtual = 0
	order by `tabDocType`.read_only, `tabDocType`.in_create""",
	"""select `tabCustom Field`.dt as parent,
		`tabDocType`.read_only, `tabDocType`.in_create,
		`tabCustom Field`.fieldname, `tabCustom Field`.options
	from `tabCustom Field`, `tabDocType`
	where `tabCustom Field`.fieldtype='Dynamic Link' and
	`tabDocType`.`name`=`tabCustom Field`.dt
	order by `tabDocType`.read_only, `tabDocType`.in_create""",
]


def get_dynamic_link_map(for_delete=False) -> dict:
	"""Build a map of all dynamically linked tables. For example,
	        if Note is dynamically linked to ToDo, the function will return
	        `{"Note": ["ToDo"], "Sales Invoice": ["Journal Entry Detail"]}`

	Note: Will not map single doctypes
	"""

	# Datahenge: This is huge performance hit; I've made it better via Redis Cache. 
	# CLI: bench execute frappe.model.dynamic_links.get_dynamic_link_map

	# Datahenge: Try to fetch from Redis cache first, instead of doing loops and SQL.
	coded_result = frappe.cache().hgetall("dh_dynamic_link_map")
	if coded_result:
		# print("INFO: Using Datahenge cached 'dh_dynamic_link_map'")
		result = {}
		for key, data in sorted(coded_result.items()):
			result[key.decode()] = data  # need to decode the binary Keys into Strings
		return result

	# Datahenge: Otherwise, attempt to find Dynamic Link Map via the usual Frappe Framework methods.
	# NOTE: Database Admins should take care that all "Link" DocFields have an appropriate SQL index.

	if getattr(frappe.local, "dynamic_link_map", None) is None or frappe.flags.in_test:
		# Build the map from scratch
		print("NOTE: Building a 'dynamic_link_map' map from scratch via loops and SQL queries...")
		dynamic_link_map = {}
		for df in get_dynamic_links():
			meta = frappe.get_meta(df.parent)
			if meta.issingle:
				# always check in Single DocTypes
				dynamic_link_map.setdefault(meta.name, []).append(df)
			else:
				try:
					links = frappe.db.sql_list(
						"""select distinct `{options}` from `tab{parent}`""".format(**df)
					)
					for doctype in links:
						dynamic_link_map.setdefault(doctype, []).append(df)
				except frappe.db.TableMissingError:
					pass

		frappe.local.dynamic_link_map = dynamic_link_map

		# Datahenge : Now that we have this data, save in Redis, so all subsequent calls are very fast.
		if dynamic_link_map:
			print("INFO: Writing contents of dynamic_link_map to Redis cache key 'dh_dynamic_link_map'")
			for key, value in dynamic_link_map.items():
				frappe.cache().hset("dh_dynamic_link_map", key, value)  # pretty sure Frappe's dictionary has a key of None?
		else:
			frappe.msgprint("WARNING: Suspiciously found nothing in dynamic_link_map.items()", to_console=True)

	return frappe.local.dynamic_link_map


def get_dynamic_links():
	"""Return list of dynamic link fields as DocField.
	Uses cache if possible"""
	df = []
	for query in dynamic_link_queries:
		df += frappe.db.sql(query, as_dict=True)
	return df
