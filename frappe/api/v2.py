"""REST API v2

This file defines routes and implementation for REST API.

Note:
	- All functions in this file should be treated as "whitelisted" as they are exposed via routes
	- None of the functions present here should be called from python code, their location and
	  internal implementation can change without treating it as "breaking change".
"""
import json
from typing import Any

from six import iteritems
from werkzeug.routing import Rule

import frappe
import frappe.client
from frappe import _, get_newargs, is_whitelisted, Document as DocumentType
from frappe.core.doctype.server_script.server_script_utils import get_server_script_map
from frappe.handler import is_valid_http_method, run_server_script, upload_file
from frappe.utils.response import build_response


PERMISSION_MAP = {
	"GET": "read",
	"POST": "write",
}


def handle_rpc_call(method: str, doctype: str | None = None):
	from frappe.modules.utils import load_doctype_module

	if doctype:
		# Expand to run actual method from doctype controller
		module = load_doctype_module(doctype)
		method = module.__name__ + "." + method

	for hook in reversed(frappe.get_hooks("override_whitelisted_methods", {}).get(method, [])):
		# override using the last hook
		method = hook
		break

	# via server script
	server_script = get_server_script_map().get("_api", {}).get(method)
	if server_script:
		return run_server_script(server_script)

	try:
		method = frappe.get_attr(method)
	except Exception as e:
		frappe.throw(_("Failed to get method {0} with {1}").format(method, e))

	is_whitelisted(method)
	is_valid_http_method(method)

	return frappe.call(method, **frappe.form_dict)


def login():
	"""Login happens implicitly, this function doesn't do anything."""
	pass


def logout():
	frappe.local.login_manager.logout()
	frappe.db.commit()


def read_doc(doctype: str, name: str):
	doc = frappe.get_doc(doctype, name)
	doc.check_permission("read")
	doc.apply_fieldlevel_read_permissions()
	return doc


def document_list(doctype: str):
	if frappe.form_dict.get("fields"):
		frappe.form_dict["fields"] = json.loads(frappe.form_dict["fields"])

	# set limit of records for frappe.get_list
	frappe.form_dict.limit_page_length = frappe.form_dict.limit or 20
	# evaluate frappe.get_list
	return frappe.call(frappe.client.get_list, doctype, **frappe.form_dict)


def count(doctype: str) -> int:
	from frappe.desk.reportview import get_count

	frappe.form_dict.doctype = doctype

	return get_count()


def create_doc(doctype: str):
	data = frappe.form_dict
	data.pop("doctype", None)
	# Farm To People, Datahenge
	# Hard to believe this is not standard code.  During POST, if a 'name' is passed,
	# but a record with that name already exists?  Throw an Error.
	if 'name' in data and frappe.db.exists(doctype, data['name']):
		raise frappe.NameError(f"API Error: Calling POST with a 'name' value ({data['name']}) that already exists.")
	# End of Fix
	return frappe.new_doc(doctype, **data).insert()


def update_doc(doctype: str, name: str):
	data = frappe.form_dict

	doc = frappe.get_doc(doctype, name, for_update=True)
	data.pop("flags", None)

	if not can_update_dh(doc, new_data=data):
		return build_response("json")
	doc.update(data)
	doc.save()

	# -------------------------------
	# Datahenge and Farm To People.
	# -------------------------------
	# The next few lines of code are a BIG DEAL.
	# What happens is when a Child DocType is saved, the ENTIRE parent DocType is save()
	# This can result in a HUGE ripple effect of unwanted code execution and validation
	#
	# Consider a Web Subscription with 20 Lines.  One line is touched by a PUT.  This results
	# in a save() to the Parent.  That save() executes before_validate(), validate(), before_save(),
	# a SQL UPDATE to the table, on_update() and on_change().
	#
	# Not only that.  But VERY LIKELY the parent calls validation() on EVERY child item.
	# Even though none of them were ever modified.
	#
	# So.  I'm going to comment-out the next few lines of Code.
	# And force each Child DocType to decide (on its own)
	# what Parent code to call during a PUT, if any.

	# check for child table doctype
	#if doc.get("parenttype"):
	#	frappe.get_doc(doc.parenttype, doc.parent).save()

	return doc


def delete_doc(doctype: str, name: str):
	frappe.client.delete_doc(doctype, name)
	frappe.response.http_status_code = 202
	return "ok"


def get_meta(doctype: str):
	frappe.only_for("All")
	return frappe.get_meta(doctype)


def execute_doc_method(doctype: str, name: str, method: str | None = None):
	"""Get a document from DB and execute method on it.

	Use cases:
	- Submitting/cancelling document
	- Triggering some kind of update on a document
	"""
	method = method or frappe.form_dict.pop("run_method")
	doc = frappe.get_doc(doctype, name)
	doc.is_whitelisted(method)

	doc.check_permission(PERMISSION_MAP[frappe.request.method])
	return doc.run_method(method, **frappe.form_dict)


def run_doc_method(method: str, document: dict[str, Any] | str, kwargs=None):
	"""run a whitelisted controller method on in-memory document.


	This is useful for building clients that don't necessarily encode all the business logic but
	call server side function on object to validate and modify the doc.

	The doc CAN exists in DB too and can write to DB as well if method is POST.
	"""

	if isinstance(document, str):
		document = frappe.parse_json(document)

	if kwargs is None:
		kwargs = {}

	doc = frappe.get_doc(document)
	doc._original_modified = doc.modified
	doc.check_if_latest()

	doc.check_permission(PERMISSION_MAP[frappe.request.method])

	method_obj = getattr(doc, method)
	fn = getattr(method_obj, "__func__", method_obj)
	is_whitelisted(fn)
	is_valid_http_method(fn)

	new_kwargs = get_newargs(fn, kwargs)
	response = doc.run_method(method, **new_kwargs)
	frappe.response.docs.append(doc)  # send modified document and result both.
	return response


def can_update_dh(doc, new_data):
	"""
	Datahenge: Logic to be called during a PUT, to prevent updating of Read Only fields.
	"""

	# Arguments:
		# doc: 			Document attempting to modify.
		# new_data		a Frappe Dictionary of new values.

	if not isinstance(doc, DocumentType):
		raise TypeError("Argument 'doc' is not an instance of Document.")

	meta = frappe.get_meta(doc.doctype, cached=False)
	docfield_meta = meta.get("fields")  # a List of DocField

	# Concept: If nothing in the payload is a CRUD, don't bother with the PUT
	payload_contains_changes = False  # pylint: disable=unused-variable

	for key, new_value in iteritems(new_data):
		current_value = doc.get(key)
		if new_value != current_value:
			payload_contains_changes = True
			# print(f"Attempting to change value of {key} from '{current_value}' to '{new_value}'")
			try:
				docfield = next(field for field in docfield_meta if field.fieldname == key)
			except StopIteration as ex:
				raise ValueError(f"No such field '{key}' exists in document {doc.doctype}.") from ex

			# If trying a PUT on a read-only field, throw an error.
			if docfield.fieldtype == 'Read Only':
				raise frappe.MethodNotAllowed(f"Cannot modify the value of a 'Read Only' column '{key}' via API PUT.")
			if bool(docfield.read_only) is True:
				raise frappe.MethodNotAllowed(f"Cannot modify the value of a 'read_only' column '{key}' via API PUT.")

	# TODO: Not 100% confident this is safe, when it comes to complex PUT payloads
	#if not payload_contains_changes:
	#	print("FYI, payload of PUT contains no changes to data.")
	#	return False

	return True

url_rules = [
	# RPC calls
	Rule("/method/login", endpoint=login),
	Rule("/method/logout", endpoint=logout),
	Rule("/method/ping", endpoint=frappe.ping),
	Rule("/method/upload_file", endpoint=upload_file),
	Rule("/method/<method>", endpoint=handle_rpc_call),
	Rule(
		"/method/run_doc_method",
		methods=["GET", "POST"],
		endpoint=lambda: frappe.call(run_doc_method, **frappe.form_dict),
	),
	Rule("/method/<doctype>/<method>", endpoint=handle_rpc_call),
	# Document level APIs
	Rule("/document/<doctype>", methods=["GET"], endpoint=document_list),
	Rule("/document/<doctype>", methods=["POST"], endpoint=create_doc),
	Rule("/document/<doctype>/<path:name>/", methods=["GET"], endpoint=read_doc),
	Rule("/document/<doctype>/<path:name>/", methods=["PATCH", "PUT"], endpoint=update_doc),
	Rule("/document/<doctype>/<path:name>/", methods=["DELETE"], endpoint=delete_doc),
	Rule(
		"/document/<doctype>/<path:name>/method/<method>/",
		methods=["GET", "POST"],
		endpoint=execute_doc_method,
	),
	# Collection level APIs
	Rule("/doctype/<doctype>/meta", methods=["GET"], endpoint=get_meta),
	Rule("/doctype/<doctype>/count", methods=["GET"], endpoint=count),
]
