# -*- coding: utf-8 -*-
# Copyright (c) 2015, Frappe Technologies and contributors
# For license information, please see license.txt

from __future__ import unicode_literals

from datetime import timedelta
import functools
from jinja2 import TemplateSyntaxError
from past.builtins import cmp
from six import iteritems, string_types

import frappe
from frappe import throw, _
from frappe.utils import cstr
from frappe.model.document import Document

from frappe.model.naming import make_autoname
from frappe.core.doctype.dynamic_link.dynamic_link import deduplicate_dynamic_links

from frappe.contacts.address_and_contact import set_link_title




class Address(Document):

	# Datahenge
	def on_update(self):
		self.update_customer_borough()
		if bool(self.flags.get("dh_address_skip_orders_cascade", False)):
			pass
			# print("Address modified, but will not cascade into Daily Orders, because I was told not to...")
		else:
			self.update_daily_orders(verbose=False)

	def update_customer_borough(self):
		if (self.address_type != "Shipping") or (not self.is_shipping_address):
			return

		# Find the Customer(s) associated with this Address record.
		customer_keys = [ link.link_name for link in self.links if link.link_doctype == "Customer"]
		if not customer_keys:
			return

		if not self.pincode:
			return

		postal_code_territory: str = frappe.db.get_value("Postal Code", self.pincode[:5], "territory")  # Customer's address might be a 9-digit Zip.

		for key in customer_keys:
			doc_customer = frappe.get_doc("Customer", key)
			if doc_customer.territory != postal_code_territory:  # Territory has changed...
				doc_customer.territory = postal_code_territory
				doc_customer.db_update()  # For performance reasons, just edit the field and skip the Controller Methods

	def update_daily_orders(self, verbose=False):
		"""
		Apply new Address information to existing Daily Orders.
		"""

		from temporal import date_to_iso_string
		from temporal.core import get_system_date
		from ftp import Checkpoint

		if (self.address_type != "Shipping") or (not self.is_shipping_address):
			if verbose:
				frappe.msgprint("Address is not customer's default Shipping Address.  Daily Orders will not be updated.", level='debug')
			return

		# Find the Customer(s) associated with this Address record.
		customer_keys = [ link.link_name for link in self.links if link.link_doctype == "Customer"]
		if not customer_keys:
			return

		order_address_updated = False
		tomorrow_date = get_system_date() + timedelta(days=1)
		tomorrow_date = date_to_iso_string(tomorrow_date)
		for customer_key in customer_keys:
			# For each customer found, update the Orders.
			filters = { "delivery_date": [">=", tomorrow_date],
			            "customer": customer_key,
						"is_past_cutoff": False
			}
			daily_orders = frappe.get_list("Daily Order", filters=filters, pluck='name')
			if verbose:
				print(f"Customer address was modified. Updating {len(daily_orders)} related Daily Orders...")
				checkpoint = Checkpoint("Address Modified, Update Orders")

			for daily_order in daily_orders:
				doc_daily_order = frappe.get_doc("Daily Order", daily_order)
				doc_daily_order.set_default_address()
				doc_daily_order.save()  # January 5th 2023 : Change from db_update() to save(), to ensure that Shipping Rule is recalculated.
				order_address_updated = True
				if verbose:
					print(f"Customer account Shipping address was modified: updated related Daily Order {daily_order}")

			if verbose:
				checkpoint.elapsed()

		if order_address_updated:
			frappe.msgprint("\u2713 Updated shipping address on non-cutoff Daily Orders.")

	# End Datahenge Custom Functions

	def __setup__(self):
		self.flags.linked = False

	def autoname(self):
		if not self.address_title:
			if self.links:
				self.address_title = self.links[0].link_name

		if self.address_title:
			self.name = (cstr(self.address_title).strip() + "-" + cstr(_(self.address_type)).strip())
			if frappe.db.exists("Address", self.name):
				self.name = make_autoname(cstr(self.address_title).strip() + "-" +
					cstr(self.address_type).strip() + "-.#")
		else:
			throw(_("Address Title is mandatory."))

	def validate(self):
		self.link_address()
		self.validate_preferred_address()
		set_link_title(self)
		deduplicate_dynamic_links(self)
		self.check_for_blocked_address()


	def check_for_blocked_address(self):
		# Filter through the address doctype to check for address with the same info
		blocked_address = frappe.get_all (
			"Address",
			filters = {
				"address_line1": self.address_line1,
				"address_line2": self.address_line2,
				"city": self.city,
				"state": self.state,
				"pincode": self.pincode,
				"address_type": "Blocked (Do Not Ship)"
			},
			pluck = "name"
		)

		if blocked_address:
			frappe.throw("The shipping address for this order is marked as 'Blocked (Do Not Ship)")

	def link_address(self):
		"""Link address based on owner"""
		if not self.links:
			contact_name = frappe.db.get_value("Contact", {"email_id": self.owner})
			if contact_name:
				contact = frappe.get_cached_doc('Contact', contact_name)
				for link in contact.links:
					self.append('links', dict(link_doctype=link.link_doctype, link_name=link.link_name))
				return True

		return False

	def validate_preferred_address(self):
		preferred_fields = ['is_primary_address', 'is_shipping_address']

		for field in preferred_fields:
			if self.get(field):
				for link in self.links:
					address = get_preferred_address(link.link_doctype, link.link_name, field)

					if address:
						update_preferred_address(address, field)

	def get_display(self):
		return get_address_display(self.as_dict())

	def has_link(self, doctype, name):
		for link in self.links:
			if link.link_doctype==doctype and link.link_name== name:
				return True

	def has_common_link(self, doc):
		reference_links = [(link.link_doctype, link.link_name) for link in doc.links]
		for link in self.links:
			if (link.link_doctype, link.link_name) in reference_links:
				return True

		return False

def get_preferred_address(doctype, name, preferred_key='is_primary_address'):
	if preferred_key in ['is_shipping_address', 'is_primary_address']:
		address = frappe.db.sql(""" SELECT
				addr.name
			FROM
				`tabAddress` addr, `tabDynamic Link` dl
			WHERE
				dl.parent = addr.name and dl.link_doctype = %s and
				dl.link_name = %s and ifnull(addr.disabled, 0) = 0 and
				%s = %s
			""" % ('%s', '%s', preferred_key, '%s'), (doctype, name, 1), as_dict=1)

		if address:
			return address[0].name

	return

@frappe.whitelist()
def get_default_address(doctype, name, sort_key='is_primary_address'):
	'''Returns default Address name for the given doctype, name'''
	if sort_key not in ['is_shipping_address', 'is_primary_address']:
		return None

	out = frappe.db.sql(""" SELECT
			addr.name, addr.%s
		FROM
			`tabAddress` addr, `tabDynamic Link` dl
		WHERE
			dl.parent = addr.name and dl.link_doctype = %s and
			dl.link_name = %s and ifnull(addr.disabled, 0) = 0
		""" %(sort_key, '%s', '%s'), (doctype, name))

	if out:
		return sorted(out, key = functools.cmp_to_key(lambda x,y: cmp(y[1], x[1])))[0][0]
	else:
		return None


@frappe.whitelist()
def get_address_display(address_dict):
	if not address_dict:
		return

	if not isinstance(address_dict, dict):
		address_dict = frappe.db.get_value("Address", address_dict, "*", as_dict=True, cache=True) or {}

	name, template = get_address_templates(address_dict)

	try:
		return frappe.render_template(template, address_dict)
	except TemplateSyntaxError:
		frappe.throw(_("There is an error in your Address Template {0}").format(name))


def get_territory_from_address(address):
	"""Tries to match city, state and country of address to existing territory"""
	if not address:
		return

	if isinstance(address, string_types):
		address = frappe.get_cached_doc("Address", address)

	territory = None
	for fieldname in ("city", "state", "country"):
		if address.get(fieldname):
			territory = frappe.db.get_value("Territory", address.get(fieldname))
			if territory:
				break

	return territory

def get_list_context(context=None):
	return {
		"title": _("Addresses"),
		"get_list": get_address_list,
		"row_template": "templates/includes/address_row.html",
		'no_breadcrumbs': True,
	}

def get_address_list(doctype, txt, filters, limit_start, limit_page_length = 20, order_by = None):
	from frappe.www.list import get_list
	user = frappe.session.user
	ignore_permissions = True

	if not filters: filters = []
	filters.append(("Address", "owner", "=", user))

	return get_list(doctype, txt, filters, limit_start, limit_page_length, ignore_permissions=ignore_permissions)

def has_website_permission(doc, ptype, user, verbose=False):
	"""Returns true if there is a related lead or contact related to this document"""
	contact_name = frappe.db.get_value("Contact", {"email_id": frappe.session.user})
	if contact_name:
		contact = frappe.get_doc('Contact', contact_name)
		return contact.has_common_link(doc)

		lead_name = frappe.db.get_value("Lead", {"email_id": frappe.session.user})
		if lead_name:
			return doc.has_link('Lead', lead_name)

	return False

def get_address_templates(address):
	result = frappe.db.get_value("Address Template", \
		{"country": address.get("country")}, ["name", "template"])

	if not result:
		result = frappe.db.get_value("Address Template", \
			{"is_default": 1}, ["name", "template"])

	if not result:
		frappe.throw(_("No default Address Template found. Please create a new one from Setup > Printing and Branding > Address Template."))
	else:
		return result

def get_company_address(company):
	ret = frappe._dict()
	ret.company_address = get_default_address('Company', company)
	ret.company_address_display = get_address_display(ret.company_address)

	return ret

@frappe.whitelist()
@frappe.validate_and_sanitize_search_inputs
def address_query(doctype, txt, searchfield, start, page_len, filters):
	from frappe.desk.reportview import get_match_cond

	link_doctype = filters.pop('link_doctype')
	link_name = filters.pop('link_name')

	condition = ""
	meta = frappe.get_meta("Address")
	for fieldname, value in iteritems(filters):
		if meta.get_field(fieldname) or fieldname in frappe.db.DEFAULT_COLUMNS:
			condition += " and {field}={value}".format(
				field=fieldname,
				value=frappe.db.escape(value))

	searchfields = meta.get_search_fields()

	if searchfield and (meta.get_field(searchfield)\
				or searchfield in frappe.db.DEFAULT_COLUMNS):
		searchfields.append(searchfield)

	search_condition = ''
	for field in searchfields:
		if search_condition == '':
			search_condition += '`tabAddress`.`{field}` like %(txt)s'.format(field=field)
		else:
			search_condition += ' or `tabAddress`.`{field}` like %(txt)s'.format(field=field)

	return frappe.db.sql("""select
			`tabAddress`.name, `tabAddress`.city, `tabAddress`.country
		from
			`tabAddress`, `tabDynamic Link`
		where
			`tabDynamic Link`.parent = `tabAddress`.name and
			`tabDynamic Link`.parenttype = 'Address' and
			`tabDynamic Link`.link_doctype = %(link_doctype)s and
			`tabDynamic Link`.link_name = %(link_name)s and
			ifnull(`tabAddress`.disabled, 0) = 0 and
			({search_condition})
			{mcond} {condition}
		order by
			if(locate(%(_txt)s, `tabAddress`.name), locate(%(_txt)s, `tabAddress`.name), 99999),
			`tabAddress`.idx desc, `tabAddress`.name
		limit %(start)s, %(page_len)s """.format(
			mcond=get_match_cond(doctype),
			key=searchfield,
			search_condition = search_condition,
			condition=condition or ""), {
			'txt': '%' + txt + '%',
			'_txt': txt.replace("%", ""),
			'start': start,
			'page_len': page_len,
			'link_name': link_name,
			'link_doctype': link_doctype
		})

def get_condensed_address(doc):
	fields = ["address_title", "address_line1", "address_line2", "city", "county", "state", "country"]
	return ", ".join([doc.get(d) for d in fields if doc.get(d)])

def update_preferred_address(address, field):
	frappe.db.set_value('Address', address, field, 0)
