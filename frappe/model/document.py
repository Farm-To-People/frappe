# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE
import hashlib
import json
import time

from werkzeug.exceptions import NotFound

import frappe
from frappe import _, is_whitelisted, msgprint
from frappe.core.doctype.server_script.server_script_utils import run_server_script_for_doc_event
from frappe.desk.form.document_follow import follow_document
from frappe.integrations.doctype.webhook import run_webhooks
from frappe.model import optional_fields, table_fields
from frappe.model.base_document import BaseDocument, get_controller
from frappe.model.docstatus import DocStatus
from frappe.model.naming import set_new_name, validate_name
from frappe.model.utils import is_virtual_doctype
from frappe.model.workflow import set_workflow_state_on_action, validate_workflow
from frappe.utils import cstr, date_diff, file_lock, flt, get_datetime_str, now
from frappe.utils.data import get_absolute_url
from frappe.utils.global_search import update_global_search


# Datahenge Variables
DEBUG_ENV_VARIABLE="FTP_DEBUG_DOCUMENT"  # if this OS environment variable = 1, then dprint() messages will print to stdout.

def get_doc(*args, **kwargs):
	"""returns a frappe.model.Document object.

	:param arg1: Document dict or DocType name.
	:param arg2: [optional] document name.
	:param for_update: [optional] select document for update.

	There are multiple ways to call `get_doc`

	        # will fetch the latest user object (with child table) from the database
	        user = get_doc("User", "test@example.com")

	        # create a new object
	        user = get_doc({
	                "doctype":"User"
	                "email_id": "test@example.com",
	                "roles: [
	                        {"role": "System Manager"}
	                ]
	        })

	        # create new object with keyword arguments
	        user = get_doc(doctype='User', email_id='test@example.com')

	        # select a document for update
	        user = get_doc("User", "test@example.com", for_update=True)
	"""
	if args:
		if isinstance(args[0], BaseDocument):
			# already a document
			return args[0]
		elif isinstance(args[0], str):
			doctype = args[0]

		elif isinstance(args[0], dict):
			# passed a dict
			kwargs = args[0]

		else:
			raise ValueError("First non keyword argument must be a string or dict")

		# Datahenge: It's possible to make a Date the primary key (name) of a DocType.  When doing so, make sure to call with strings.
		if (len(args) > 1) and isinstance(args[1], date_type):
			raise ValueError('When calling get_doc(), second non keyword argument cannot be a Date object (use an ISO String instead)')

	if len(args) < 2 and kwargs:
		if "doctype" in kwargs:
			doctype = kwargs["doctype"]
		else:
			raise ValueError('"doctype" is a required key')

	controller = get_controller(doctype)
	if controller:
		return controller(*args, **kwargs)

	raise ImportError(doctype)


class Document(BaseDocument):
	"""All controllers inherit from `Document`."""

	def __init__(self, *args, **kwargs):
		"""Constructor.

		:param arg1: DocType name as string or document **dict**
		:param arg2: Document name, if `arg1` is DocType name.

		If DocType name and document name are passed, the object will load
		all values (including child documents) from the database.
		"""
		self.doctype = None
		self.name = None
		self.flags = frappe._dict()

		if args and args[0]:
			if isinstance(args[0], str):
				# first arugment is doctype
				self.doctype = args[0]

				# doctype for singles, string value or filters for other documents
				self.name = self.doctype if len(args) == 1 else args[1]

				# for_update is set in flags to avoid changing load_from_db signature
				# since it is used in virtual doctypes and inherited in child classes
				self.flags.for_update = kwargs.get("for_update")
				self.load_from_db()
				# Datahenge: Would be lovely to set the 'parent_doc' here, but we run into infinite recursion  :/				
				return

			if isinstance(args[0], dict):
				# first argument is a dict
				kwargs = args[0]

		if kwargs:
			# init base document
			super().__init__(kwargs)
			self.init_child_tables()
			self.init_valid_columns()

		else:
			# incorrect arguments. let's not proceed.
			raise ValueError("Illegal arguments")

	@staticmethod
	def whitelist(fn):
		"""Decorator: Whitelist method to be called remotely via REST API."""
		frappe.whitelist()(fn)
		return fn

	def load_from_db(self):
		"""Load document and children from database and create properties
		from fields"""
		self.flags.ignore_children = True
		if not getattr(self, "_metaclass", False) and self.meta.issingle:
			single_doc = frappe.db.get_singles_dict(self.doctype, for_update=self.flags.for_update)
			if not single_doc:
				single_doc = frappe.new_doc(self.doctype, as_dict=True)
				single_doc["name"] = self.doctype
				del single_doc["__islocal"]

			super().__init__(single_doc)
			self.init_valid_columns()
			self._fix_numeric_types()

		else:
			d = frappe.db.get_value(
				self.doctype, self.name, "*", as_dict=1, for_update=self.flags.for_update
			)
			if not d:
				# TODO: Find a way to prevent this from throwing, when purposely
				# Doing a try/catch maneuver, to prevent 2 SQL calls (exists + get_doc)
				frappe.throw(
					_("{0} {1} not found").format(_(self.doctype), self.name), frappe.DoesNotExistError
				)

			super().__init__(d)
		self.flags.pop("ignore_children", None)

		for df in self._get_table_fields():
			# Make sure not to query the DB for a child table, if it is a virtual one.
			# During frappe is installed, the property "is_virtual" is not available in tabDocType, so
			# we need to filter those cases for the access to frappe.db.get_value() as it would crash otherwise.
			if hasattr(self, "doctype") and not hasattr(self, "module") and is_virtual_doctype(df.options):
				self.set(df.fieldname, [])
				continue

			children = (
				frappe.db.get_values(
					df.options,
					{"parent": self.name, "parenttype": self.doctype, "parentfield": df.fieldname},
					"*",
					as_dict=True,
					order_by="idx asc",
					for_update=self.flags.for_update,
				)
				or []
			)

			self.set(df.fieldname, children)

		# sometimes __setup__ can depend on child values, hence calling again at the end
		if hasattr(self, "__setup__"):
			self.__setup__()

	def reload(self):
		"""Reload document from database"""
		self.load_from_db()

	def get_latest(self):
		if not getattr(self, "_doc_before_save", None):
			self.load_doc_before_save()

		return self._doc_before_save

	def check_permission(self, permtype="read", permlevel=None):
		"""Raise `frappe.PermissionError` if not permitted"""
		if not self.has_permission(permtype):
			self.raise_no_permission_to(permlevel or permtype)

	def has_permission(self, permtype="read", verbose=False) -> bool:
		"""
		Call `frappe.permissions.has_permission` if `ignore_permissions` flag isn't truthy

		:param permtype: `read`, `write`, `submit`, `cancel`, `delete`, etc.
		:param verbose: DEPRECATED, will be removed in a future release.
		"""

		if self.flags.ignore_permissions:
			return True

		import frappe.permissions

		return frappe.permissions.has_permission(self.doctype, permtype, self)

	def raise_no_permission_to(self, perm_type):
		"""Raise `frappe.PermissionError`."""
		frappe.flags.error_message = _("Insufficient Permission for {0}").format(self.doctype)
		raise frappe.PermissionError

	def insert(
		self,
		ignore_permissions=None,
		ignore_links=None,
		ignore_if_duplicate=False,
		ignore_mandatory=None,
		set_name=None,
		set_child_names=True,
	) -> "Document":
		"""Insert the document in the database (as a new document).
		This will check for user permissions and execute `before_insert`,
		`validate`, `on_update`, `after_insert` methods if they are written.

		:param ignore_permissions: Do not check permissions if True."""
		if self.flags.in_print:
			return

		self.flags.notifications_executed = []

		if ignore_permissions is not None:
			self.flags.ignore_permissions = ignore_permissions

		if ignore_links is not None:
			self.flags.ignore_links = ignore_links

		if ignore_mandatory is not None:
			self.flags.ignore_mandatory = ignore_mandatory

		self.set("__islocal", True)

		self._set_defaults()
		self.set_user_and_timestamp()
		self.set_docstatus()
		self.check_if_latest()
		self._prevalidate_links()	# Datahenge, need a means of running some additional code first.
		self._validate_links()
		self.check_permission("create")
		self.run_method("before_insert")
		self.set_new_name(set_name=set_name, set_child_names=set_child_names)
		self.set_parent_in_children()
		self.validate_higher_perm_levels()

		self.flags.in_insert = True

		self.run_before_validate_methods()  # Datahenge: New function.
		self._validate()  # Flipped, was the second call
		self.run_before_save_methods()  # Flipped, was the first call.  This calls Custom Controllers, like validate()

		self.set_docstatus()
		self.flags.in_insert = False

		# run validate, on update etc.

		# parent
		if getattr(self.meta, "issingle", 0):
			self.update_single(self.get_valid_dict())
		else:
			self.db_insert(ignore_if_duplicate=ignore_if_duplicate)

		# children
		for d in self.get_all_children():
			d.db_insert()

		self.run_method("after_insert")
		self.flags.in_insert = True

		if self.get("amended_from"):
			self.copy_attachments_from_amended_from()

		# flag to prevent creation of event update log for create and update both
		# during document creation
		self.flags.update_log_for_doc_creation = True
		self.run_post_save_methods()
		self.flags.in_insert = False

		# delete __islocal
		if hasattr(self, "__islocal"):
			delattr(self, "__islocal")

		# clear unsaved flag
		if hasattr(self, "__unsaved"):
			delattr(self, "__unsaved")

		if not (
			frappe.flags.in_migrate or frappe.local.flags.in_install or frappe.flags.in_setup_wizard
		):
			if frappe.get_cached_value("User", frappe.session.user, "follow_created_documents"):
				follow_document(self.doctype, self.name, frappe.session.user)
		return self

	def save(self, *args, **kwargs):
		"""Wrapper for _save"""
		return self._save(*args, **kwargs)

	def _save(self, ignore_permissions=None, ignore_version=None) -> "Document":
		"""Save the current document in the database in the **DocType**'s table or
		`tabSingles` (for single types).

		This will check for user permissions and execute
		`validate` before updating, `on_update` after updating triggers.

		:param ignore_permissions: Do not check permissions if True.
		:param ignore_version: Do not save version if True."""
		if self.flags.in_print:
			return

		self.flags.notifications_executed = []

		if ignore_permissions is not None:
			self.flags.ignore_permissions = ignore_permissions

		self.flags.ignore_version = frappe.flags.in_test if ignore_version is None else ignore_version

		if self.get("__islocal") or not self.get("name"):
			return self.insert()

		self.check_permission("write", "save")

		self.set_user_and_timestamp()
		self.set_docstatus()
		self.check_if_latest()
		self.set_parent_in_children()
		self.set_name_in_children()

		self.validate_higher_perm_levels()  # DH: This function modified.
		self._prevalidate_links()	# DH: Need to introduce a way of running Document-based code, prior to Link validation.
		self._validate_links()  # note: this call also validates the Links of child documents.
		# self.run_before_save_methods()

		# --------
		# Datahenge:
		# --------
		# I have deliberately switched the positions of:
		# 		run_before_save_methods()
		# 		_self._validate()
  		#
		# Why?  Because it's crazy otherwise.  Because then validate() would be called before any
		# Link Validation or Mandatory fields were checked!  Your custom Controller code could be dealing with
		# unexpected NULLs, or broken links.

		self.run_before_validate_methods()  # Datahenge: before_validate() must happen early.

		if self._action != "cancel":
			self._validate()  # This calls useful validations like Links and Mandatory fields.

		self.run_before_save_methods()  # This calls Document-specific Controller Methods, like validate()

		if self._action == "update_after_submit":
			self.validate_update_after_submit()

		self.set_docstatus()

		# parent
		if self.meta.issingle:
			self.update_single(self.get_valid_dict())
		else:
			self.db_update()

		self.update_children()
		self.run_post_save_methods()

		# clear unsaved flag
		if hasattr(self, "__unsaved"):
			delattr(self, "__unsaved")

		return self

	def copy_attachments_from_amended_from(self):
		"""Copy attachments from `amended_from`"""
		from frappe.desk.form.load import get_attachments

		# loop through attachments
		for attach_item in get_attachments(self.doctype, self.amended_from):

			# save attachments to new doc
			_file = frappe.get_doc(
				{
					"doctype": "File",
					"file_url": attach_item.file_url,
					"file_name": attach_item.file_name,
					"attached_to_name": self.name,
					"attached_to_doctype": self.doctype,
					"folder": "Home/Attachments",
				}
			)
			_file.save()

	def update_children(self):
		"""update child tables"""
		for df in self.meta.get_table_fields():
			self.update_child_table(df.fieldname, df)

	def update_child_table(self, fieldname, df=None):
		"""sync child table for given fieldname"""
		rows = []
		if not df:
			df = self.meta.get_field(fieldname)

		for d in self.get(df.fieldname):
			d.db_update()
			rows.append(d.name)

		if (
			df.options in (self.flags.ignore_children_type or [])
			or frappe.get_meta(df.options).is_virtual == 1
		):
			# do not delete rows for this because of flags
			# hack for docperm :(
			return

		if rows:
			# select rows that do not match the ones in the document
			deleted_rows = frappe.db.sql(
				"""select name from `tab{}` where parent=%s
				and parenttype=%s and parentfield=%s
				and name not in ({})""".format(
					df.options, ",".join(["%s"] * len(rows))
				),
				[self.name, self.doctype, fieldname] + rows,
			)
			if len(deleted_rows) > 0:
				# delete rows that do not match the ones in the document
				frappe.db.delete(df.options, {"name": ("in", tuple(row[0] for row in deleted_rows))})

		else:
			# no rows found, delete all rows
			frappe.db.delete(
				df.options, {"parent": self.name, "parenttype": self.doctype, "parentfield": fieldname}
			)

	def get_doc_before_save(self):
		return getattr(self, "_doc_before_save", None)

	def has_value_changed(self, fieldname, ignore_new=False, debug=False):
		"""Returns true if value is changed before and after saving"""
		# Datahenge : Add the ability to ignore new records.
		previous = self.get_doc_before_save()
		if ignore_new and (not previous):
			return False
		if not previous:
			if debug:
				print(f"Warning: No previous value found for field '{fieldname}'; returning a True.")
			return True
		if debug:
			print(f"has_value_changed() Before: {previous.get(fieldname)}, After: {self.get(fieldname)}")
		return previous.get(fieldname) != self.get(fieldname) if previous else True

	def set_new_name(self, force=False, set_name=None, set_child_names=True):
		"""Calls `frappe.naming.set_new_name` for parent and child docs."""

		if self.flags.name_set and not force:
			return

		# If autoname has set as Prompt (name)
		if self.get("__newname"):
			self.name = validate_name(self.doctype, self.get("__newname"))
			self.flags.name_set = True
			return

		if set_name:
			self.name = validate_name(self.doctype, set_name)
		else:
			set_new_name(self)

		if set_child_names:
			# set name for children
			for d in self.get_all_children():
				set_new_name(d)

		self.flags.name_set = True

	def get_title(self):
		"""Get the document title based on title_field or `title` or `name`"""
		return self.get(self.meta.get_title_field()) or ""

	def set_title_field(self):
		"""Set title field based on template"""

		def get_values():
			values = self.as_dict()
			# format values
			for key, value in values.items():
				if value is None:
					values[key] = ""
			return values

		if self.meta.get("title_field") == "title":
			df = self.meta.get_field(self.meta.title_field)

			if df.options:
				self.set(df.fieldname, df.options.format(**get_values()))
			elif self.is_new() and not self.get(df.fieldname) and df.default:
				# set default title for new transactions (if default)
				self.set(df.fieldname, df.default.format(**get_values()))

	def update_single(self, d):
		"""Updates values for Single type Document in `tabSingles`."""
		frappe.db.delete("Singles", {"doctype": self.doctype})
		for field, value in d.items():
			if field != "doctype":
				frappe.db.sql(
					"""insert into `tabSingles` (doctype, field, value)
					values (%s, %s, %s)""",
					(self.doctype, field, value),
				)

		if self.doctype in frappe.db.value_cache:
			del frappe.db.value_cache[self.doctype]

	def set_user_and_timestamp(self):
		self._original_modified = self.modified
		self.modified = now()
		self.modified_by = frappe.session.user

		# We'd probably want the creation and owner to be set via API
		# or Data import at some point, that'd have to be handled here
		if self.is_new() and not (
			frappe.flags.in_install or frappe.flags.in_patch or frappe.flags.in_migrate
		):
			self.creation = self.modified
			self.owner = self.modified_by

		for d in self.get_all_children():
			d.modified = self.modified
			d.modified_by = self.modified_by
			if not d.owner:
				d.owner = self.owner
			if not d.creation:
				d.creation = self.creation

		frappe.flags.currently_saving.append((self.doctype, self.name))

	def set_docstatus(self):
		if self.docstatus is None:
			self.docstatus = DocStatus.draft()

		for d in self.get_all_children():
			d.docstatus = self.docstatus

	def _validate(self):
		self.load_doc_before_save()  # Datahenge: Moving here to ensure it's always called.
		self._validate_mandatory()
		self._validate_data_fields()
		self._validate_selects()
		self._validate_non_negative()
		self._validate_length()
		self._validate_code_fields()
		self._sync_autoname_field()
		self._extract_images_from_text_editor()
		self._sanitize_content()
		self._save_passwords()
		self.validate_workflow()

		for d in self.get_all_children():
			d._validate_data_fields()
			d._validate_selects()
			d._validate_non_negative()
			d._validate_length()
			d._validate_code_fields()
			d._sync_autoname_field()
			d._extract_images_from_text_editor()
			d._sanitize_content()
			d._save_passwords()
		if self.is_new():
			# don't set fields like _assign, _comments for new doc
			for fieldname in optional_fields:
				self.set(fieldname, None)
		else:
			self.validate_set_only_once()

	def _validate_non_negative(self):
		def get_msg(df):
			if self.get("parentfield"):
				return "{} {} #{}: {} {}".format(
					frappe.bold(_(self.doctype)),
					_("Row"),
					self.idx,
					_("Value cannot be negative for"),
					frappe.bold(_(df.label)),
				)
			else:
				return _("Value cannot be negative for {0}: {1}").format(
					_(df.parent), frappe.bold(_(df.label))
				)

		for df in self.meta.get(
			"fields", {"non_negative": ("=", 1), "fieldtype": ("in", ["Int", "Float", "Currency"])}
		):

			if flt(self.get(df.fieldname)) < 0:
				msg = get_msg(df)
				frappe.throw(msg, frappe.NonNegativeError, title=_("Negative Value"))

	def validate_workflow(self):
		"""Validate if the workflow transition is valid"""
		if frappe.flags.in_install == "frappe":
			return
		workflow = self.meta.get_workflow()
		if workflow:
			validate_workflow(self)
			if not self._action == "save":
				set_workflow_state_on_action(self, workflow, self._action)

	def validate_set_only_once(self):
		"""Validate that fields are not changed if not in insert"""
		set_only_once_fields = self.meta.get_set_only_once_fields()

		if set_only_once_fields and self._doc_before_save:
			# document exists before saving
			for field in set_only_once_fields:
				fail = False
				value = self.get(field.fieldname)
				original_value = self._doc_before_save.get(field.fieldname)

				if field.fieldtype in table_fields:
					fail = not self.is_child_table_same(field.fieldname)
				elif field.fieldtype in ("Date", "Datetime", "Time"):
					fail = str(value) != str(original_value)
				else:
					fail = value != original_value

				if fail:
					# Datahenge: Improved on the message here.
					frappe.throw(
						_("Value cannot be changed for field {0} (Set Once Only)").format(
							frappe.bold(self.meta.get_label(field.fieldname))
						),
						exc=frappe.CannotChangeConstantError,
					)

		return False

	def is_child_table_same(self, fieldname):
		"""Validate child table is same as original table before saving"""
		# Datahenge: Disadvantage is only 1 field at a time.  And doesn't return -how- they are different.
		value = self.get(fieldname)
		original_value = self._doc_before_save.get(fieldname)
		same = True

		if len(original_value) != len(value):
			same = False
		else:
			# check all child entries
			for i, d in enumerate(original_value):
				new_child = value[i].as_dict(convert_dates_to_str=True)
				original_child = d.as_dict(convert_dates_to_str=True)

				# all fields must be same other than modified and modified_by
				for key in ("modified", "modified_by", "creation"):
					del new_child[key]
					del original_child[key]

				if original_child != new_child:
					same = False
					break

		return same

	def apply_fieldlevel_read_permissions(self):
		"""Remove values the user is not allowed to read (called when loading in desk)"""

		if frappe.session.user == "Administrator":
			return

		has_higher_permlevel = False

		all_fields = self.meta.fields.copy()
		for table_field in self.meta.get_table_fields():
			all_fields += frappe.get_meta(table_field.options).fields or []

		for df in all_fields:
			if df.permlevel > 0:
				has_higher_permlevel = True
				break

		if not has_higher_permlevel:
			return

		has_access_to = self.get_permlevel_access("read")

		for df in self.meta.fields:
			if df.permlevel and not df.permlevel in has_access_to:
				self.set(df.fieldname, None)

		for table_field in self.meta.get_table_fields():
			for df in frappe.get_meta(table_field.options).fields or []:
				if df.permlevel and not df.permlevel in has_access_to:
					for child in self.get(table_field.fieldname) or []:
						child.set(df.fieldname, None)

	def validate_higher_perm_levels(self):
		"""If the user does not have permissions at permlevel > 0, then reset the values to original / default"""
		if self.flags.ignore_permissions or frappe.flags.in_install:
			return

		if frappe.session.user == "Administrator":
			return

		has_access_to = self.get_permlevel_access()
		high_permlevel_fields = self.meta.get_high_permlevel_fields()

		if high_permlevel_fields:
			self.reset_values_if_no_permlevel_access(has_access_to, high_permlevel_fields)

		# If new record then don't reset the values for child table
		if self.is_new():
			return

		# check for child tables
		for df in self.meta.get_table_fields():
			high_permlevel_fields = frappe.get_meta(df.options).get_high_permlevel_fields()
			if high_permlevel_fields:
				for d in self.get(df.fieldname):
					# Datahenge: The call below can cause havoc if DocField permissions are not carefully set.
					d.reset_values_if_no_permlevel_access(has_access_to, high_permlevel_fields)

	def get_permlevel_access(self, permission_type="write"):
		allowed_permlevels = []
		roles = frappe.get_roles()

		for perm in self.get_permissions():
			if (
				perm.role in roles and perm.get(permission_type) and perm.permlevel not in allowed_permlevels
			):
				allowed_permlevels.append(perm.permlevel)

		return allowed_permlevels

	def has_permlevel_access_to(self, fieldname, df=None, permission_type="read"):
		if not df:
			df = self.meta.get_field(fieldname)

		return df.permlevel in self.get_permlevel_access(permission_type)

	def get_permissions(self):
		if self.meta.istable:
			# use parent permissions
			permissions = frappe.get_meta(self.parenttype).permissions
		else:
			permissions = self.meta.permissions

		return permissions

	def _set_defaults(self):
		if frappe.flags.in_import:
			return

		new_doc = frappe.new_doc(self.doctype, as_dict=True)
		self.update_if_missing(new_doc)

		# children
		for df in self.meta.get_table_fields():
			new_doc = frappe.new_doc(df.options, as_dict=True)
			value = self.get(df.fieldname)
			if isinstance(value, list):
				for d in value:
					d.update_if_missing(new_doc)

	def check_if_latest(self):
		"""Checks if `modified` timestamp provided by document being updated is same as the
		`modified` timestamp in the database. If there is a different, the document has been
		updated in the database after the current copy was read. Will throw an error if
		timestamps don't match.

		Will also validate document transitions (Save > Submit > Cancel) calling
		`self.check_docstatus_transition`."""

		self.load_doc_before_save(raise_exception=True)

		self._action = "save"
		previous = self._doc_before_save

		# previous is None for new document insert
		if not previous:
			self.check_docstatus_transition(0)
			return

		if cstr(previous.modified) != cstr(self._original_modified):
			frappe.msgprint(
				_("Error: Document has been modified after you have opened it")
				+ (f" ({previous.modified}, {self.modified}). ")
				+ _("Please refresh to get the latest document."),
				raise_exception=frappe.TimestampMismatchError,
			)

		if not self.meta.issingle:
			self.check_docstatus_transition(previous.docstatus)

	def check_docstatus_transition(self, to_docstatus):
		"""Ensures valid `docstatus` transition.
		Valid transitions are (number in brackets is `docstatus`):

		- Save (0) > Save (0)
		- Save (0) > Submit (1)
		- Submit (1) > Submit (1)
		- Submit (1) > Cancel (2)

		"""
		if not self.docstatus:
			self.docstatus = DocStatus.draft()

		if to_docstatus == DocStatus.draft():
			if self.docstatus.is_draft():
				self._action = "save"
			elif self.docstatus.is_submitted():
				self._action = "submit"
				self.check_permission("submit")
			elif self.docstatus.is_cancelled():
				raise frappe.DocstatusTransitionError(
					_("Cannot change docstatus from 0 (Draft) to 2 (Cancelled)")
				)
			else:
				raise frappe.ValidationError(_("Invalid docstatus"), self.docstatus)

		elif to_docstatus == DocStatus.submitted():
			if self.docstatus.is_submitted():
				self._action = "update_after_submit"
				self.check_permission("submit")
			elif self.docstatus.is_cancelled():
				self._action = "cancel"
				self.check_permission("cancel")
			elif self.docstatus.is_draft():
				raise frappe.DocstatusTransitionError(
					_("Cannot change docstatus from 1 (Submitted) to 0 (Draft)")
				)
			else:
				raise frappe.ValidationError(_("Invalid docstatus"), self.docstatus)

		elif to_docstatus == DocStatus.cancelled():
			raise frappe.ValidationError(_("Cannot edit cancelled document"))

	def set_parent_in_children(self):
		"""Updates `parent` and `parenttype` property in all children."""
		for d in self.get_all_children():
			d.parent = self.name
			d.parenttype = self.doctype

	def set_name_in_children(self):
		# Set name for any new children
		for d in self.get_all_children():
			if not d.name:
				set_new_name(d)

	def validate_update_after_submit(self):
		if self.flags.ignore_validate_update_after_submit:
			return

		self._validate_update_after_submit()
		for d in self.get_all_children():
			if d.is_new() and self.meta.get_field(d.parentfield).allow_on_submit:
				# in case of a new row, don't validate allow on submit, if table is allow on submit
				continue

			d._validate_update_after_submit()

		# TODO check only allowed values are updated

	def _validate_mandatory(self):
		if self.flags.ignore_mandatory:
			return

		missing = self._get_missing_mandatory_fields()
		for d in self.get_all_children():
			missing.extend(d._get_missing_mandatory_fields())

		if not missing:
			return

		for fieldname, msg in missing:
			msgprint(msg)

		if frappe.flags.print_messages:
			print(self.as_json().encode("utf-8"))

		raise frappe.MandatoryError(
			"[{doctype}, {name}]: {fields}".format(
				fields=", ".join(each[0] for each in missing), doctype=self.doctype, name=self.name
			)
		)

	def _validate_links(self):
		if self.flags.ignore_links or \
			(hasattr(self, '_action') and self._action == "cancel"):  # Datahenge: Sometimes you want to Validate Links without an Action.
			return

		invalid_links, cancelled_links = self.get_invalid_links()

		for d in self.get_all_children():
			result = d.get_invalid_links(is_submittable=self.meta.is_submittable)
			invalid_links.extend(result[0])
			cancelled_links.extend(result[1])

		if invalid_links:
			msg = ", ".join(each[2] for each in invalid_links)
			frappe.throw(_(f"Invalid link in DocType '{self.doctype}'. Could not find {msg}"),
				frappe.LinkValidationError)

		if cancelled_links:
			msg = ", ".join(each[2] for each in cancelled_links)
			frappe.throw(_("Cannot link cancelled document: {0}").format(msg), frappe.CancelledLinkError)

	def get_all_children(self, parenttype=None) -> list["Document"]:
		"""Returns all children documents from **Table** type fields in a list."""

		children = []

		for df in self.meta.get_table_fields():
			if parenttype and df.options != parenttype:
				continue

			if value := self.get(df.fieldname):
				children.extend(value)

		return children

	def run_method(self, method, *args, **kwargs):
		"""run standard triggers, plus those in hooks"""

		def fn(self, *args, **kwargs):
			method_object = getattr(self, method, None)

			# Cannot have a field with same name as method
			# If method found in __dict__, expect it to be callable
			if method in self.__dict__ or callable(method_object):
				return method_object(*args, **kwargs)

		fn.__name__ = str(method)
		out = Document.hook(fn)(self, *args, **kwargs)

		self.run_notifications(method)
		run_webhooks(self, method)
		run_server_script_for_doc_event(self, method)

		return out

	def run_trigger(self, method, *args, **kwargs):
		return self.run_method(method, *args, **kwargs)

	def run_notifications(self, method):
		"""Run notifications for this method"""
		if (
			(frappe.flags.in_import and frappe.flags.mute_emails)
			or frappe.flags.in_patch
			or frappe.flags.in_install
		):
			return

		if self.flags.notifications_executed is None:
			self.flags.notifications_executed = []

		from frappe.email.doctype.notification.notification import evaluate_alert

		if self.flags.notifications is None:

			def _get_notifications():
				"""returns enabled notifications for the current doctype"""

				return frappe.get_all(
					"Notification",
					fields=["name", "event", "method"],
					filters={"enabled": 1, "document_type": self.doctype},
				)

			self.flags.notifications = frappe.cache().hget(
				"notifications", self.doctype, _get_notifications
			)

		if not self.flags.notifications:
			return

		def _evaluate_alert(alert):
			if not alert.name in self.flags.notifications_executed:
				evaluate_alert(self, alert.name, alert.event)
				self.flags.notifications_executed.append(alert.name)

		event_map = {
			"on_update": "Save",
			"after_insert": "New",
			"on_submit": "Submit",
			"on_cancel": "Cancel",
		}

		if not self.flags.in_insert:
			# value change is not applicable in insert
			event_map["on_change"] = "Value Change"

		for alert in self.flags.notifications:
			event = event_map.get(method, None)
			if event and alert.event == event:
				_evaluate_alert(alert)
			elif alert.event == "Method" and method == alert.method:
				_evaluate_alert(alert)

	@whitelist.__func__
	def _submit(self):
		"""Submit the document. Sets `docstatus` = 1, then saves."""
		self.docstatus = DocStatus.submitted()
		try:
			return self.save()
		except Exception as ex:
			self.docstatus = 0  # NOTE: Was very shocked I had to add this.  Do I need to rollback too?
			frappe.whatis("What we have here is a failure to Submit.  Ideally, should this not rollback?", frontend=False)
			raise ex

	@whitelist.__func__
	def _cancel(self):
		"""Cancel the document. Sets `docstatus` = 2, then saves."""
		self.docstatus = DocStatus.cancelled()
		return self.save()

	@whitelist.__func__
	def _rename(
		self, name: str, merge: bool = False, force: bool = False, validate_rename: bool = True
	):
		"""Rename the document. Triggers frappe.rename_doc, then reloads."""
		from frappe.model.rename_doc import rename_doc

		self.name = rename_doc(doc=self, new=name, merge=merge, force=force, validate=validate_rename)
		self.reload()

	@whitelist.__func__
	def submit(self):
		"""Submit the document. Sets `docstatus` = 1, then saves."""
		return self._submit()

	@whitelist.__func__
	def cancel(self):
		"""Cancel the document. Sets `docstatus` = 2, then saves."""
		return self._cancel()

	@whitelist.__func__
	def rename(
		self, name: str, merge: bool = False, force: bool = False, validate_rename: bool = True
	):
		"""Rename the document to `name`. This transforms the current object."""
		return self._rename(name=name, merge=merge, force=force, validate_rename=validate_rename)

	def delete(self, ignore_permissions=False):
		"""Delete document."""
		return frappe.delete_doc(
			self.doctype, self.name, ignore_permissions=ignore_permissions, flags=self.flags
		)

	def delete_improved(self, **kwargs):
		"""
		Datahenge: An improved and more-complete delete method.

		kwargs:
 			force
			ignore_doctypes
			for_reload
			ignore_permissions
			flags
			ignore_on_trash
			ignore_missing
			delete_permanently

		This function was created because of the need to:
			1. Ignore link validation when deleting Daily Order lines that are Farm Box parents (pointed at by adjacent Order Lines)
			2. Pass custom flags like "delete_parent_if_empty" to Controller methods like on_trash() and after_delete()

		This was not possible with out-of-the-box Frappe delete() or delete_doc()
		"""
		import frappe.model.delete_doc	as delete_doc_module

		# One very-useful flag is the 'delete_parent_if_empty'
		if not kwargs:
			kwargs = {"flags": self.flags}
		else:
			kwargs['flags'] = self.flags

		delete_doc_module.delete_doc(
			self.doctype,
			self.name,
			**kwargs)


	def run_before_validate_methods(self):
		"""
		Datahenge: Moving 'before_validate' in here, so we can do some work prior to
		           validating Links, Mandatory fields, and validate() calls.
		"""
		self.load_doc_before_save()

		# before_validate method should be executed before ignoring validations
		if self._action in ("save", "submit"):
			self.run_method("before_validate")


	def run_before_save_methods(self):
		"""Run standard methods before	`INSERT` or `UPDATE`. Standard Methods are:

		- `validate`, `before_save` for **Save**.
		- `validate`, `before_submit` for **Submit**.
		- `before_cancel` for **Cancel**
		- `before_update_after_submit` for **Update after Submit**

		Will also update title_field if set"""

		self.reset_seen()

		# Datahenge: Removed before_validate() below, because it was happening too late (after Link and Mandatory checks)
		# before_validate method should be executed before ignoring validations
		#if self._action in ("save", "submit"):
		#	self.run_method("before_validate")

		if self.flags.ignore_validate:
			return

		if self._action == "save":
			self.run_method("validate")
			self.run_method("before_save")
		elif self._action == "submit":
			self.run_method("validate")
			self.run_method("before_submit")
		elif self._action == "cancel":
			self.run_method("before_cancel")
		elif self._action == "update_after_submit":
			self.run_method("before_update_after_submit")

		self.set_title_field()

	def load_doc_before_save(self, *, raise_exception: bool = False):
		"""load existing document from db before saving"""

		self._doc_before_save = None

		if self.is_new():
			return

		try:
			self._doc_before_save = frappe.get_doc(self.doctype, self.name, for_update=True)
		except frappe.DoesNotExistError:
			if raise_exception:
				raise

			frappe.clear_last_message()

	def run_post_save_methods(self):
		"""Run standard methods after `INSERT` or `UPDATE`. Standard Methods are:

		- `on_update` for **Save**.
		- `on_update`, `on_submit` for **Submit**.
		- `on_cancel` for **Cancel**
		- `update_after_submit` for **Update after Submit**"""

		if self._action == "save":
			self.run_method("on_update")
		elif self._action == "submit":
			self.run_method("on_update")
			self.run_method("on_submit")
		elif self._action == "cancel":
			self.run_method("on_cancel")
			self.check_no_back_links_exist()
		elif self._action == "update_after_submit":
			self.run_method("on_update_after_submit")

		self.clear_cache()

		if self.flags.get("notify_update", True):
			self.notify_update()

		update_global_search(self)

		self.save_version()

		self.run_method("on_change")

		if (self.doctype, self.name) in frappe.flags.currently_saving:
			frappe.flags.currently_saving.remove((self.doctype, self.name))

	def clear_cache(self):
		frappe.clear_document_cache(self.doctype, self.name)

	def reset_seen(self):
		"""Clear _seen property and set current user as seen"""
		if getattr(self.meta, "track_seen", False):
			frappe.db.set_value(
				self.doctype, self.name, "_seen", json.dumps([frappe.session.user]), update_modified=False
			)

	def notify_update(self):
		"""Publish realtime that the current document is modified"""
		if frappe.flags.in_patch:
			return

		frappe.publish_realtime(
			"doc_update",
			{"modified": self.modified, "doctype": self.doctype, "name": self.name},
			doctype=self.doctype,
			docname=self.name,
			after_commit=True,
		)

		if (
			not self.meta.get("read_only")
			and not self.meta.get("issingle")
			and not self.meta.get("istable")
		):
			data = {"doctype": self.doctype, "name": self.name, "user": frappe.session.user}
			frappe.publish_realtime("list_update", data, after_commit=True)

	def db_set(self, fieldname, value=None, update_modified=True, notify=False, commit=False):
		"""Set a value in the document object, update the timestamp and update the database.

		WARNING: This method does not trigger controller validations and should
		be used very carefully.

		:param fieldname: fieldname of the property to be updated, or a {"field":"value"} dictionary
		:param value: value of the property to be updated
		:param update_modified: default True. updates the `modified` and `modified_by` properties
		:param notify: default False. run doc.notify_update() to send updates via socketio
		:param commit: default False. run frappe.db.commit()
		"""
		if isinstance(fieldname, dict):
			self.update(fieldname)
		else:
			self.set(fieldname, value)

		if update_modified and (self.doctype, self.name) not in frappe.flags.currently_saving:
			# don't update modified timestamp if called from post save methods
			# like on_update or on_submit
			self.set("modified", now())
			self.set("modified_by", frappe.session.user)

		# load but do not reload doc_before_save because before_change or on_change might expect it
		if not self.get_doc_before_save():
			self.load_doc_before_save()

		# to trigger notification on value change
		self.run_method("before_change")

		if self.name is None:
			return

		frappe.db.set_value(
			self.doctype,
			self.name,
			fieldname,
			value,
			self.modified,
			self.modified_by,
			update_modified=update_modified,
		)

		self.run_method("on_change")

		if notify:
			self.notify_update()

		self.clear_cache()
		if commit:
			frappe.db.commit()

	def db_get(self, fieldname):
		"""get database value for this fieldname"""
		return frappe.db.get_value(self.doctype, self.name, fieldname)

	def check_no_back_links_exist(self):
		"""Check if document links to any active document before Cancel."""
		from frappe.model.delete_doc import check_if_doc_is_dynamically_linked, check_if_doc_is_linked

		if not self.flags.ignore_links:
			check_if_doc_is_linked(self, method="Cancel")
			check_if_doc_is_dynamically_linked(self, method="Cancel")

	def save_version(self):
		"""Save version info"""

		# don't track version under following conditions
		if (
			not getattr(self.meta, "track_changes", False)
			or self.doctype == "Version"
			or self.flags.ignore_version
			or frappe.flags.in_install
			or (not self._doc_before_save and frappe.flags.in_patch)
		):
			return

		version = frappe.new_doc("Version")

		if is_useful_diff := version.update_version_info(self._doc_before_save, self):
			version.insert(ignore_permissions=True)

			if not frappe.flags.in_migrate:
				# follow since you made a change?
				if frappe.get_cached_value("User", frappe.session.user, "follow_created_documents"):
					follow_document(self.doctype, self.name, frappe.session.user)

	@staticmethod
	def hook(f):
		"""Decorator: Make method `hookable` (i.e. extensible by another app).

		Note: If each hooked method returns a value (dict), then all returns are
		collated in one dict and returned. Ideally, don't return values in hookable
		methods, set properties in the document."""

		def add_to_return_value(self, new_return_value):
			if new_return_value is None:
				self._return_value = self.get("_return_value")
				return

			if isinstance(new_return_value, dict):
				if not self.get("_return_value"):
					self._return_value = {}
				self._return_value.update(new_return_value)
			else:
				self._return_value = new_return_value

		def compose(fn, *hooks):
			def runner(self, method, *args, **kwargs):
				add_to_return_value(self, fn(self, *args, **kwargs))
				for f in hooks:
					add_to_return_value(self, f(self, method, *args, **kwargs))

				return self.__dict__.pop("_return_value", None)

			return runner

		def composer(self, *args, **kwargs):
			hooks = []
			method = f.__name__
			doc_events = frappe.get_doc_hooks()
			for handler in doc_events.get(self.doctype, {}).get(method, []) + doc_events.get("*", {}).get(
				method, []
			):
				hooks.append(frappe.get_attr(handler))

			composed = compose(f, *hooks)
			return composed(self, method, *args, **kwargs)

		return composer

	def is_whitelisted(self, method_name):
		method = getattr(self, method_name, None)
		if not method:
			raise NotFound(f"Method {method_name} not found")

		is_whitelisted(getattr(method, "__func__", method))

	def validate_value(self, fieldname, condition, val2, doc=None, raise_exception=None):
		"""Check that value of fieldname should be 'condition' val2
		else throw Exception."""
		error_condition_map = {
			"in": _("one of"),
			"not in": _("none of"),
			"^": _("beginning with"),
		}

		if not doc:
			doc = self

		val1 = doc.get_value(fieldname)

		df = doc.meta.get_field(fieldname)
		val2 = doc.cast(val2, df)

		if not frappe.compare(val1, condition, val2):
			label = doc.meta.get_label(fieldname)
			condition_str = error_condition_map.get(condition, condition)
			if doc.get("parentfield"):
				msg = _("Incorrect value in row {0}: {1} must be {2} {3}").format(
					doc.idx, label, condition_str, val2
				)
			else:
				msg = _("Incorrect value: {0} must be {1} {2}").format(label, condition_str, val2)

			# raise passed exception or True
			msgprint(msg, raise_exception=raise_exception or True)

	def validate_table_has_rows(self, parentfield, raise_exception=None):
		"""Raise exception if Table field is empty."""
		if not (isinstance(self.get(parentfield), list) and len(self.get(parentfield)) > 0):
			label = self.meta.get_label(parentfield)
			frappe.throw(
				_("Table {0} cannot be empty").format(label), raise_exception or frappe.EmptyTableError
			)

	def round_floats_in(self, doc, fieldnames=None):
		"""Round floats for all `Currency`, `Float`, `Percent` fields for the given doc.

		:param doc: Document whose numeric properties are to be rounded.
		:param fieldnames: [Optional] List of fields to be rounded."""
		if not fieldnames:
			fieldnames = (
				df.fieldname
				for df in doc.meta.get("fields", {"fieldtype": ["in", ["Currency", "Float", "Percent"]]})
			)

		for fieldname in fieldnames:
			doc.set(fieldname, flt(doc.get(fieldname), self.precision(fieldname, doc.get("parentfield"))))

	def get_url(self):
		"""Returns Desk URL for this document."""
		return get_absolute_url(self.doctype, self.name)

	def add_comment(
		self,
		comment_type="Comment",
		text=None,
		comment_email=None,
		link_doctype=None,
		link_name=None,
		comment_by=None,
	):
		"""Add a comment to this document.

		:param comment_type: e.g. `Comment`. See Communication for more info."""

		out = frappe.get_doc(
			{
				"doctype": "Comment",
				"comment_type": comment_type,
				"comment_email": comment_email or frappe.session.user,
				"comment_by": comment_by,
				"reference_doctype": self.doctype,
				"reference_name": self.name,
				"content": text or comment_type,
				"link_doctype": link_doctype,
				"link_name": link_name,
			}
		).insert(ignore_permissions=True)
		return out

	def add_seen(self, user=None):
		"""add the given/current user to list of users who have seen this document (_seen)"""
		if not user:
			user = frappe.session.user

		if self.meta.track_seen and not frappe.flags.read_only:
			_seen = self.get("_seen") or []
			_seen = frappe.parse_json(_seen)

			if user not in _seen:
				_seen.append(user)
				frappe.db.set_value(self.doctype, self.name, "_seen", json.dumps(_seen), update_modified=False)
				frappe.local.flags.commit = True

	def add_viewed(self, user=None):
		"""add log to communication when a user views a document"""
		if not user:
			user = frappe.session.user

		if hasattr(self.meta, "track_views") and self.meta.track_views:
			view_log = frappe.get_doc(
				{
					"doctype": "View Log",
					"viewed_by": frappe.session.user,
					"reference_doctype": self.doctype,
					"reference_name": self.name,
				}
			)
			if frappe.flags.read_only:
				view_log.deferred_insert()
			else:
				view_log.insert(ignore_permissions=True)
				frappe.local.flags.commit = True

	def log_error(self, title=None, message=None):
		"""Helper function to create an Error Log"""
		return frappe.log_error(
			message=message, title=title, reference_doctype=self.doctype, reference_name=self.name
		)

	def get_signature(self):
		"""Returns signature (hash) for private URL."""
		return hashlib.sha224(get_datetime_str(self.creation).encode()).hexdigest()

	def get_document_share_key(self, expires_on=None, no_expiry=False):
		if no_expiry:
			expires_on = None

		existing_key = frappe.db.exists(
			"Document Share Key",
			{
				"reference_doctype": self.doctype,
				"reference_docname": self.name,
				"expires_on": expires_on,
			},
		)
		if existing_key:
			doc = frappe.get_doc("Document Share Key", existing_key)
		else:
			doc = frappe.new_doc("Document Share Key")
			doc.reference_doctype = self.doctype
			doc.reference_docname = self.name
			doc.expires_on = expires_on
			doc.flags.no_expiry = no_expiry
			doc.insert(ignore_permissions=True)

		return doc.key

	def get_liked_by(self):
		liked_by = getattr(self, "_liked_by", None)
		if liked_by:
			return json.loads(liked_by)
		else:
			return []

	def set_onload(self, key, value):
		if not self.get("__onload"):
			self.set("__onload", frappe._dict())
		self.get("__onload")[key] = value

	def get_onload(self, key=None):
		if not key:
			return self.get("__onload", frappe._dict())

		return self.get("__onload")[key]

	def queue_action(self, action, **kwargs):
		"""Run an action in background. If the action has an inner function,
		like _submit for submit, it will call that instead"""
		# call _submit instead of submit, so you can override submit to call
		# run_delayed based on some action
		# See: Stock Reconciliation
		from frappe.utils.background_jobs import enqueue

		if hasattr(self, f"_{action}"):
			action = f"_{action}"

		try:
			self.lock()
		except frappe.DocumentLockedError:
			frappe.throw(
				_("This document is currently queued for execution. Please try again"),
				title=_("Document Queued"),
			)

		return enqueue(
			"frappe.model.document.execute_action",
			__doctype=self.doctype,
			__name=self.name,
			__action=action,
			**kwargs,
		)

	def lock(self, timeout=None):
		"""Creates a lock file for the given document. If timeout is set,
		it will retry every 1 second for acquiring the lock again

		:param timeout: Timeout in seconds, default 0"""
		signature = self.get_signature()
		if file_lock.lock_exists(signature):
			lock_exists = True
			if timeout:
				for i in range(timeout):
					time.sleep(1)
					if not file_lock.lock_exists(signature):
						lock_exists = False
						break
			if lock_exists:
				raise frappe.DocumentLockedError
		file_lock.create_lock(signature)
		frappe.local.locked_documents.append(self)

	def unlock(self):
		"""Delete the lock file for this document"""
		file_lock.delete_lock(self.get_signature())
		if self in frappe.local.locked_documents:
			frappe.local.locked_documents.remove(self)

	# validation helpers
	def validate_from_to_dates(self, from_date_field, to_date_field):
		"""
		Generic validation to verify date sequence
		"""
		if date_diff(self.get(to_date_field), self.get(from_date_field)) < 0:
			frappe.throw(
				_("{0} must be after {1}").format(
					frappe.bold(self.meta.get_label(to_date_field)),
					frappe.bold(self.meta.get_label(from_date_field)),
				),
				frappe.exceptions.InvalidDates,
			)

	def get_assigned_users(self):
		assigned_users = frappe.get_all(
			"ToDo",
			fields=["allocated_to"],
			filters={
				"reference_type": self.doctype,
				"reference_name": self.name,
				"status": ("!=", "Cancelled"),
			},
			pluck="allocated_to",
		)

		users = set(assigned_users)
		return users

	def add_tag(self, tag):
		"""Add a Tag to this document"""
		from frappe.desk.doctype.tag.tag import DocTags

		DocTags(self.doctype).add(self.name, tag)

	def get_tags(self):
		"""Return a list of Tags attached to this document"""
		from frappe.desk.doctype.tag.tag import DocTags

		return DocTags(self.doctype).get_tags(self.name).split(",")[1:]

	def deferred_insert(self) -> None:
		"""Push the document to redis temporarily and insert later.

		WARN: This doesn't guarantee insertion as redis can be restarted
		before data is flushed to database.
		"""

		from frappe.deferred_insert import deferred_insert

		self.set_user_and_timestamp()

		doc = self.get_valid_dict(convert_dates_to_str=True, ignore_virtual=True)
		deferred_insert(doctype=self.doctype, records=doc)

	def __repr__(self):
		name = self.name or "unsaved"
		doctype = self.__class__.__name__

		docstatus = f" docstatus={self.docstatus}" if self.docstatus else ""
		parent = f" parent={self.parent}" if getattr(self, "parent", None) else ""

		return f"<{doctype}: {name}{docstatus}{parent}>"

	def __str__(self):
		name = self.name or "unsaved"
		doctype = self.__class__.__name__

		return f"{doctype}({name})"

	# -------------------------------
	# DATHENGE: Magic Happens Here:
	# -------------------------------
	DH_DEBUG = False


	def _prevalidate_links(self, **kwargs):  # pylint: disable=unused-argument
		"""
		Datahenge: An opportunity to execute some code, just prior to Link validation.
		# This is useful is situations where you know Links might be a problem.
		# And you want a change to do some pre-cleaning first.
		"""
		for doc in self.get_all_children():
			doc.run_method("_prevalidate_links", _parent_doc=self)

	def get_parent_doc(self, new_parent_doc=None):
		"""
		Return a child document's parent document.
		Created By Datahenge
		"""
		if new_parent_doc:
			self.parent_doc = new_parent_doc
			return self.parent_doc
		if hasattr(self, 'parent_doc') and self.parent_doc:
			return self.parent_doc
		self.parent_doc = self.read_parent_doc_from_db()
		return self.parent_doc

	def read_parent_doc_from_db(self):
		"""
		Return a document's parent document from SQL
		Created By Datahenge
		"""
		if self.parenttype and self.parent:
			return frappe.get_doc(self.parenttype, self.parent)
		raise ValueError(f"Document '{self.name}' of type '{self.doctype}' does not have a parent Document.")


	def reload_child_table(self, docfield_fieldname):
		"""
		Datahenge: What if I want to reread just a Child table from SQL, without rereading all
		the other DocFields on this Doctype?

		Now, I think can...
		"""
		try:
			df = next(iter([ table_field for table_field in self.meta.get_table_fields()
			                 if table_field.fieldname == docfield_fieldname]))
		except StopIteration:
			raise Exception(f"DocType '{self.name}' does not have a Table field named '{docfield_fieldname}'")

		children = frappe.db.get_values(df.options,
			{"parent": self.name, "parenttype": self.doctype, "parentfield": df.fieldname},
			"*", as_dict=True, order_by="idx asc")
		if children:
			self.set(df.fieldname, children)
		else:
			self.set(df.fieldname, [])

	def is_child_doctype(self):
		"""
		Returns a True if this document is a child DocType.
		"""
		return bool(frappe.get_meta(self.doctype).istable)  # the poorly-named 'istable' DocType metadata

	def summarize_children(self, prefix=None):
		"""
		Print a list of child documents to the console.
		"""
		print("\n--------")
		for d in self.get_all_children():
			print(f"* {prefix or ''} Child Record.  DocType: {d.doctype}, ID: {d.name}")
		print("--------\n")

	# --------
	# VALIDATION
	# --------

	def before_validate_children(self, child_docfield_name):
		"""
		Run the 'before_validate' code on all Child Documents.

		NOTE: If a Child document is being inserted, this calls the 'before_insert' function also.
		"""
		if not isinstance(child_docfield_name, str):
			raise ValueError("Argument 'child_docfield_name' should be a String.")
		for child_doc in self.get(child_docfield_name):
			if child_doc.is_new() and hasattr(child_doc, 'before_insert'):
				child_doc.before_insert(_parent_doc=self)
			if hasattr(child_doc, 'before_validate'):
				child_doc.before_validate(_parent_doc=self)

	def validate_children(self, child_docfield_name, **kwargs):
		"""
		Datahenge: A controller function for validating Child Doctypes.
		"""
		if not isinstance(child_docfield_name, str):
			raise ValueError("Argument 'child_docfield_name' should be a String.")

		for child_doc in self.get(child_docfield_name):
			if hasattr(child_doc, 'validate'):
				child_doc.validate(_parent_doc=self, **kwargs)

	def before_save_children(self, child_docfield_name, **kwargs):
		"""
		Datahenge: A controller function for validating Child Doctypes.
		"""
		if not isinstance(child_docfield_name, str):
			raise ValueError("Argument 'child_docfield_name' should be a String.")

		for child_doc in self.get(child_docfield_name):
			if hasattr(child_doc, 'before_save'):
				child_doc.before_save(_parent_doc=self, **kwargs)

	# --------
	# DELETION
	# --------

	def on_trash_children(self, child_docfield_name):
		"""
		If the parent document is pending deletion, cascade the 'on_trash' function to the child documents.
		"""
		self.set("__indelete", True)  # Indicates to the child document that parent is undergoing deletion.
		if not isinstance(child_docfield_name, str):
			raise ValueError("Argument 'child_docfield_name' should be a String.")
		for child_doc in self.get(child_docfield_name):
			if hasattr(child_doc, 'on_trash'):
				child_doc.on_trash(_parent_doc=self)

	def after_delete_children(self, child_docfield_name):
		"""
		After the parent document is deleted, call the 'on_delete' methods of the child documents.
		"""
		if not isinstance(child_docfield_name, str):
			raise ValueError("Argument 'child_docfield_name' should be a String.")
		for child_doc in self.get(child_docfield_name):
			if hasattr(child_doc, 'after_delete'):
				child_doc.after_delete(_parent_doc=self)

	# --------
	# UPDATES
	# --------

	def on_update_children(self, child_docfield_name, debug=DH_DEBUG):
		"""
		This function analyzes a Parent's child records, and based on CRUD, intelligently calls Child DocType controllers.
		"""
		dprint(f"\nEntering 'on_update_children' for DocType '{self.doctype}', Child '{child_docfield_name}'...", debug)

		current_child_records = self.get(child_docfield_name)
		doc_orig = self.get_doc_before_save()

		if not doc_orig:
			# Scenario 1: Parent is a new Document, therefore any Child is also new.
			if not current_child_records:
				dprint(f"* Scenario 0, New Parent: ({self.doctype}, {self.name}) has no children of DocType '{child_docfield_name}'", debug)
				return
			for child_record in current_child_records:
				dprint(f"* Scenario 1, New Parent: ({self.doctype}, {self.name}), Child: ({child_record.doctype}, {child_record.name})", debug)
				if hasattr(child_record, 'after_insert'):
					child_record.after_insert(_parent_doc=self)
				if hasattr(child_record, 'on_update'):
					child_record.on_update(_parent_doc=self)
			return

		original_child_records = doc_orig.get(child_docfield_name)
		if (not current_child_records) and (not original_child_records):
			# Scenario 2: There are no children now, and were not before.  Nothing to analyze.
			dprint(f"* Scenario 2, Parent had/has no children of DocType {child_docfield_name}", debug)
			return

		# Scenario 3: Parent is an existing Document, and some Child documents are in play.
		dprint(f"Quantity child records Before update: {len(original_child_records) or 0}", debug)
		dprint(f"Quantity child records After update: {len(current_child_records) or 0}", debug)

		docs_deleted = [ child_orig for child_orig in original_child_records
		                 if child_orig.name not in [ child.name for child in current_child_records]
		               ]

		if docs_deleted:
			# Scenario 3A: Pre-existing child documents were Deleted
			for deleted_doc in docs_deleted:
				dprint(f"* Scenario 3: Child document of type '{deleted_doc.doctype}' was Deleted.\n", debug)
				if hasattr(deleted_doc, 'on_trash'):
					deleted_doc.on_trash(_parent_doc=self)  # call controller method 'on_trash' for this Child record.
				if hasattr(deleted_doc, 'after_delete'):
					deleted_doc.after_delete(_parent_doc=self)  # call controller method 'after_delete' for this Child record.

		# Loop through all the children post-update:
		for child_doc in current_child_records:

			if child_doc.name not in [ child_orig.name for child_orig in original_child_records]:
				# Scenario 3B: Some child documents were Inserted.
				dprint(f"* Scenario 4: Child with identifier '{child_doc.name}' was Inserted.", debug)
				if hasattr(child_doc, 'after_insert'):
					child_doc.after_insert(_parent_doc=self)
				if hasattr(child_doc, 'on_update'):
					child_doc.on_update(_parent_doc=self)
				if hasattr(child_doc, 'on_change'):
					child_doc.on_change(_parent_doc=self)
				continue  # Move to next child record.

			# Child record existed before & after; compare them.
			child_orig = next(iter([ child_orig for child_orig in original_child_records if child_orig.name == child_doc.name ]))

			if _exist_significant_differences(child_orig, child_doc):
				# Scenario 2C: Some child document was Modified.
				dprint(f"* Scenario 5: Child with identifier '{child_doc.name}' was Modified.\n", debug)
				if hasattr(child_doc, 'on_update'):
					child_doc.on_update(_parent_doc=self)
				if hasattr(child_doc, 'on_change'):
					child_doc.on_change(_parent_doc=self)
			else:
				dprint(f"* Scenario 6: Child with identifier '{child_doc.name}' was Untouched.\n", debug)


	def set_parent_doc(self, _parent_doc=None):
		"""
		Datahenge: Function to assign a class variable 'parent_doc' of type Document Class.
		"""
		DEBUG = False

		if _parent_doc and not isinstance(_parent_doc, Document):
			raise TypeError("Argument '_parent_doc' is not a Document type.")

		# Scenario 1, an argument was provided, so accept it as fact, and apply it.
		if _parent_doc:
			self.parent_doc = _parent_doc
			if DEBUG:
				print(f"Scenario 1: Argument for parent_doc() was passed (caller = {self.doctype}")
			return self.parent_doc

		# Scenario 2:  This document instance already has a previously set value; so use that.
		if hasattr(self, 'parent_doc') and self.parent_doc:
			if DEBUG:
				print(f"Scenario 2: parent_doc() previously set for this document. (caller = {self.doctype}")
			return self.parent_doc

		# Scenario 3: No choice but to try reading from the SQL database.
		self.parent_doc = self.get_parent_doc()
		if DEBUG:
			print(f"Scenario 3: Argument for parent_doc() fetched from SQL database. {self.doctype}")

		if self.parent_doc:
			return self.parent_doc
		raise ValueError(f"Function 'set_parent_doc()' was unable to find a parent for calling Document {self.doctype} - {self.name}")


	def as_child_get_original_doc(self, _parent_doc=None):
		"""
		Return a copy of the original Child Document, prior to changes.
		* Custom function by Datahenge
		"""
		# from ftp.ftp_module.generics import caller_is_proxy  # deliberate late import (cross-module function)
		if not self.is_child_doctype():
			raise Exception("This function should only be called by Child DocTypes.")

		# There are 3 possibilities we have to handle:
		# 1. The child document was updated directly via a REST API call.
		# 2. The child document was updated via the ERPNext website, as a member of a Parent.
		# 3. The child document was updated by code using save()

		# This should handle Scenarios 1 and 3:
		doc_before_save = self.get_doc_before_save()
		if doc_before_save:
			return doc_before_save

		# Scenario #2 - Updated on the ERPNext website as part of a parent.
		if not _parent_doc:
			raise ValueError("Function 'as_child_get_original_doc' requires argument 'parent_doc', when called via ERPNext Website.")
		parent_orig = _parent_doc.get_doc_before_save()
		if not parent_orig:
			return None  # parent is new, therefore no original child document.
		try:
			return next(iter([ line for line in parent_orig.items if line.name == self.name ]))
		except StopIteration:
			return None  # Order Line is New.

	def set_called_via_parent(self, parent_doc=None):
		"""
		Datahenge: We used a custom "flag" attribute named "called_via_parent" to detect whether Document
		controllers were triggered by a parent (ERPNext UI), or not.
		"""
		# NOTE: Very Important to set the value inside "flags".  Otherwise, the data is lost during things like delete().

		if not self.meta.get('istable'):  # Datahenge: Terrible name.  Really means 'is_parent'
			return self.flags.pop("called_via_parent", False)  # important to set a default, or you get a Key Errror.

		if hasattr(self, "flags") and ("called_via_parent" in self.flags) and self.flags.get("called_via_parent") is True:
			return True

		if bool(parent_doc):
			self.flags.called_via_parent = True
			return True

		return False

	def get_called_via_parent(self):
		if hasattr(self, "flags") and ("called_via_parent" in self.flags) and self.flags.get("called_via_parent") is True:
			return True
		return False

# ------------------
# Non-Class methods:
# ------------------

def execute_action(__doctype, __name, __action, **kwargs):
	"""Execute an action on a document (called by background worker)"""
	doc = frappe.get_doc(__doctype, __name)
	doc.unlock()
	try:
		getattr(doc, __action)(**kwargs)
	except Exception:
		frappe.db.rollback()

		# add a comment (?)
		if frappe.local.message_log:
			msg = json.loads(frappe.local.message_log[-1]).get("message")
		else:
			msg = "<pre><code>" + frappe.get_traceback() + "</pre></code>"

		doc.add_comment("Comment", _("Action Failed") + "<br><br>" + msg)
	doc.notify_update()


# ------------------
# Datahenge Additions:
# ------------------

def get_field_differences(doc_before, doc_after,
                          error_on_type_changes=True,
						  ignore_creation=True,
                          ignore_modified=True,
						  ignore_list=None):
	"""
	Datahenge: Given 2 documents, compare values, and return a DeepDiff object.
	"""
	from deepdiff import DeepDiff
	from ftp.ftp_module.generics import doc_to_stringtyped_dict

	before = doc_to_stringtyped_dict(doc_before)
	after = doc_to_stringtyped_dict(doc_after)

	# Create a list of fields to ignore, when calculating differences.
	exclude_paths = []
	if ignore_creation:
		exclude_paths.append("root['creation']")  # ignore and strip 'creation' from the results.
		exclude_paths.append("root['owner']")  # ignore and strip 'owner' from the results.

	if ignore_modified:
		exclude_paths.append("root['modified']")  # ignore and strip 'modified' from the results.
		exclude_paths.append("root['modified_by']")  # ignore and strip 'modified_by' from the results.

	if ignore_list:
		for each in ignore_list:
			exclude_paths.append(f"root['{each}']")
	if not exclude_paths:
		exclude_paths = None

	diff = DeepDiff(before, after, exclude_paths=exclude_paths)
	if error_on_type_changes and ('type_changes' in diff.keys()):
		type_changes = diff['type_changes']
		if isinstance(type_changes, dict):
			# Scenario 1: 'type_changes' are a Dictionary:
			for key in type_changes.keys():
				old_type = type_changes[key]['old_type']
				new_type = type_changes[key]['new_type']
				NoneType = type(None)
				if (old_type == NoneType) or (new_type == NoneType):
					continue  # It's okay if either old or new is a NoneType
				raise TypeError(f"In function 'get_field_differences(), datatypes changed (Before vs. Current). {diff['type_changes']}")
		else:
			raise TypeError(f"In function 'get_field_differences(), datatypes changed (Before vs. Current). {diff['type_changes']}")

	# print(f"\nvalue of diff = \n{diff.to_dict()}\n")
	return diff


def _exist_significant_differences(document1, document2):
	"""
	Given 2 Frappe Documents, are there -significant- differences between them?
	  * Ignore creation and modified datetime differences.
	  * Ignore '__unsaved' attribute.
	  * NOTE: Must handle insanity that is Dates and Datetimes switching data-types midstream :eyeroll:
	"""

	differences = get_field_differences(document1, document2).to_dict()
	significant_differences = []

	if 'values_changed' in differences:
		for diff in differences['values_changed']:
			if diff == "root['modified']":
				continue
			#if diff[2] == [('__unsaved', 1)]:
			#	continue
			significant_differences.append(diff)

	if len(significant_differences) > 0:
		# print(f"ESD: Significant differences found between 2 documents:\n{significant_differences}")
		return True
	return False


def dprint(message, enabled=False):
	"""
	Datahenge: Quick hack for printing when needed, without fussing with a bunch of comments.
	"""
	if enabled:
		print(message)

# --------
# Datahenge
# --------

def get_document_datafield_names(doctype_name, include_child_tables=True):
	"""
	Purpose: Given any DocType's name, return the field names that are truly SQL fields.
	Datahenge: Once again, shocking this isn't part of standard Frappe framework.
	"""
	# A bit of syntax explanation: we're merging 2 lists.
	# The first is tuple 'default_fields' converted to a list.
	# The second is list comprehension, the DocFields for this DocType that are 'data_fieldtypes'
	# Finally, sort them.

	result = list(default_fields)
	result += [ docfield.fieldname for docfield in frappe.get_meta(doctype_name).fields
	            if docfield.fieldtype in data_fieldtypes]

	# Although a "Table" is not actually a SQL column, it's commonly passed as part of a JSON payload
	# when calling REST APIs.  Since that's what I designed this for, it's good to include them by default.
	if include_child_tables:
		result += [ docfield.fieldname for docfield in frappe.get_meta(doctype_name).fields
					if docfield.fieldtype in table_fields]

	return sorted(result)
