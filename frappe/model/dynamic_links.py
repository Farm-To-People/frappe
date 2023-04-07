# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals
import frappe

# select doctypes that are accessed by the user (not read_only) first, so that the
# the validation message shows the user-facing doctype first.
# For example Journal Entry should be validated before GL Entry (which is an internal doctype)

dynamic_link_queries =  [
	"""select `tabDocField`.parent,
		`tabDocType`.read_only, `tabDocType`.in_create,
		`tabDocField`.fieldname, `tabDocField`.options
	from `tabDocField`, `tabDocType`
	where `tabDocField`.fieldtype='Dynamic Link' and
	`tabDocType`.`name`=`tabDocField`.parent
	order by `tabDocType`.read_only, `tabDocType`.in_create""",

	"""select `tabCustom Field`.dt as parent,
		`tabDocType`.read_only, `tabDocType`.in_create,
		`tabCustom Field`.fieldname, `tabCustom Field`.options
	from `tabCustom Field`, `tabDocType`
	where `tabCustom Field`.fieldtype='Dynamic Link' and
	`tabDocType`.`name`=`tabCustom Field`.dt
	order by `tabDocType`.read_only, `tabDocType`.in_create""",
]

def get_dynamic_link_map():
	"""
	Build a map of all dynamically linked tables. For example,
		if Note is dynamically linked to ToDo, the function will return
		`{"Note": ["ToDo"], "Sales Invoice": ["Journal Entry Detail"]}`

	Note: Will not map single doctypes
	"""
	# NOTE: Datahenge - When not "cached" in frappe.local, this can be an expensive function.
	# NOTE: Need to ensure that "Link" DocFields always have their own SQL index.
	if getattr(frappe.local, 'dynamic_link_map', None) is None or frappe.flags.in_test:
		# Build from scratch
		dynamic_link_map = {}
		dynamic_links = get_dynamic_links()
		print(f"get_dynamic_link_map() looping through {len(dynamic_links)} links.  One SQL query required per link.")
		for df in dynamic_links:
			meta = frappe.get_meta(df.parent)
			if meta.issingle:
				# always check in Single DocTypes
				dynamic_link_map.setdefault(meta.name, []).append(df)
			else:
				try:
					links = frappe.db.sql_list("""SELECT DISTINCT {options} FROM `tab{parent}`""".format(**df), debug=False)
					for doctype in links:
						dynamic_link_map.setdefault(doctype, []).append(df)
				except frappe.db.TableMissingError: # noqa: E722
					pass

		frappe.local.dynamic_link_map = dynamic_link_map  # pylint: disable=assigning-non-slot
	return frappe.local.dynamic_link_map

def get_dynamic_links():
	'''Return list of dynamic link fields as DocField.
	Uses cache if possible'''
	df = []
	for query in dynamic_link_queries:
		df += frappe.db.sql(query, as_dict=True)
	return df
