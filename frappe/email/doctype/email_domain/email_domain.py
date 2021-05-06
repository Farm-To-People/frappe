# -*- coding: utf-8 -*-
# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and contributors
# For license information, please see license.txt

from __future__ import unicode_literals
import imaplib,poplib,smtplib

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import validate_email_address ,cint, cstr

from frappe.email.utils import get_port

class EmailDomain(Document):
	def autoname(self):
		if self.domain_name:
			self.name = self.domain_name

	# FTP: Removing the validate function.  It prevents saving the Domain before online
	# validation, which makes it awkward for correcting or debugging just 1 or 2 fields.

	def DEL_validate(self):
		"""Validate email id and check POP3/IMAP and SMTP connections is enabled."""
		if self.email_id:
			validate_email_address(self.email_id, True)

		if frappe.local.flags.in_patch or frappe.local.flags.in_test:
			return

		if not frappe.local.flags.in_install and not frappe.local.flags.in_patch:
			try:
				if self.use_imap:
					if self.use_ssl:
						test = imaplib.IMAP4_SSL(self.email_server, port=get_port(self))
					else:
						test = imaplib.IMAP4(self.email_server, port=get_port(self))

				else:
					if self.use_ssl:
						test = poplib.POP3_SSL(self.email_server, port=get_port(self))
					else:
						test = poplib.POP3(self.email_server, port=get_port(self))

			except Exception:
				frappe.throw(_("Incoming email account not correct"))
				return None
			finally:
				try:
					if self.use_imap:
						test.logout()
					else:
						test.quit()
				except Exception:
					pass
			try:
				if self.use_tls and not self.smtp_port:
					self.smtp_port = 587
				sess = smtplib.SMTP(cstr(self.smtp_server or ""), cint(self.smtp_port) or None)
				sess.quit()
			except Exception:
				frappe.throw(_("Outgoing email account not correct"))
				return None
		return

	def on_update(self):
		"""update all email accounts using this domain"""
		for email_account in frappe.get_all("Email Account",
		filters={"domain": self.name}):

			try:
				email_account = frappe.get_doc("Email Account",
					email_account.name)
				email_account.set("email_server",self.email_server)
				email_account.set("use_imap",self.use_imap)
				email_account.set("use_ssl",self.use_ssl)
				email_account.set("use_tls",self.use_tls)
				email_account.set("attachment_limit",self.attachment_limit)
				email_account.set("smtp_server",self.smtp_server)
				email_account.set("smtp_port",self.smtp_port)
				email_account.save()
			except Exception as ex:
				frappe.msgprint(email_account.name)
				frappe.throw(ex)
				return None

# Spectrum Fruits
@frappe.whitelist()
def validate_domain(email_domain_name):
	"""Validate email id and check POP3/IMAP and SMTP connections is enabled."""

	doc = frappe.get_doc("Email Domain",email_domain_name)
	if not doc:
		frappe.throw(_(f"Could not find document 'Email Domain' named '{email_domain_name}'"))

	if doc.email_id:
		validate_email_address(doc.email_id, True)

	if frappe.local.flags.in_patch:
		frappe.msgprint(_("Skipping domain tests because mode = 'in patch'"))
		return

	if frappe.local.flags.in_test:
		frappe.msgprint(_("Skipping domain tests because mode = 'in test'"))
		return

	if frappe.local.flags.in_install:
		frappe.msgprint(_("Skipping domain tests because mode = 'in install'"))
		return

	# Inbound Email (IMAP or POP3)
	try:
		if doc.use_imap:
			# IMAP
			if doc.use_ssl:
				test = imaplib.IMAP4_SSL(doc.email_server, port=get_port(doc))
			else:
				test = imaplib.IMAP4(doc.email_server, port=get_port(doc))
		else:
			# POP3
			if doc.use_ssl:
				test = poplib.POP3_SSL(doc.email_server, port=get_port(doc))
			else:
				test = poplib.POP3(doc.email_server, port=get_port(doc))
	except Exception:
		frappe.throw(_("Incoming email account not correct"))
		return None
	finally:
		try:
			if doc.use_imap:
				test.logout()
			else:
				test.quit()
		except Exception:
			pass

	# Outbound Email (SMTP)
	try:
		if doc.use_tls and not doc.smtp_port:
			doc.smtp_port = 587
			doc.save()
		sess = smtplib.SMTP(cstr(doc.smtp_server or ""), cint(doc.smtp_port) or None)
		sess.quit()
	except Exception:
		frappe.throw(_("Outgoing email account not correct"))
		return None

	frappe.msgprint(_("\u2713 Email domain '{0}' is valid.".format(email_domain_name)), indicator='green')
