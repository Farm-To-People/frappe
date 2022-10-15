""" frappe/database/datahenge.py """

# NOTE:  I'm writing this class here in Frappe App, so I don't have to worry about circular references (if I were to write in FTP, for example)

import os
# import time
import json
import frappe

class SQLTransaction():
	"""
	Datahenge: Class for tracking MySQL Transaction status.
	"""
	# NOTES:
	#
	# 0. Unlike Microsoft SQL Server, MySQL/MariaDB has no concept of nested SQL transactions, with levels/depth.
	#
	# 1. Without AUTOCOMMIT=0, a SQL "transaction" is instantiated whenever any CRUD happens.  Yes, including SELECT statements!
	# You can easily duplicate this by querying @@in_transaction, SELECT any table, then query @@in_transaction a 2nd time.
	#
	# 2. For a basic SELECT, you get a long 'trx_id' (421340439892152).  This 'trx_id' persists through multiple, subsequent SELECTs
	#
	# 3. If you follow-up with an UPDATE, you get a new, shorter trx_id (9708520), plus new Table and Row locks.
	#    Additional UPDATE statements will maintain the same trx_id.

	# Environment Variables of importance:
	#		FTP_DEBUG_SQL_TRANSACTIONS


	def __init__(self, validate_autocommit=True):

		# Optional, in case you need to verify autocommit is turned off.
		if validate_autocommit:
			SQLTransaction.err_on_autocommit()

		self.last_connection_id = None
		self.last_transaction_id = None

		env_value = os.environ.get('FTP_DEBUG_SQL_TRANSACTIONS')
		if (not env_value) or int(os.environ.get('FTP_DEBUG_SQL_TRANSACTIONS')) != 1:
			self.debug_mode = False
		else:
			self.debug_mode = True

		self.checkpoint(warn_on_changes=False)
		frappe.local.sql_transaction = self  # pylint: disable=assigning-non-slot


	def checkpoint(self, warn_on_changes=True):

		# Current MySQL Connection identifier.
		current_connection_id = SQLTransaction.get_connection_id()
		if current_connection_id != self.last_connection_id:
			if warn_on_changes:
				frappe.msgprint(f"Warning: Current SQL connection {current_connection_id} is different than last SQL connection {self.last_connection_id}")
			self.last_connection_id = current_connection_id

		current_transaction_id = None
		details = SQLTransaction.get_sql_transaction_details()
		print(details)
		if current_transaction_id != self.last_transaction_id:
			if warn_on_changes:
				frappe.msgprint(f"Warning: Current SQL Transaction {current_transaction_id} is different than last SQL transaction {self.last_transaction_id}")
			self.last_transaction_id = current_transaction_id

	@staticmethod
	def err_on_autocommit():
		query_result = frappe.db.sql("SELECT @@autocommit;")
		if query_result and query_result[0] and query_result[0][0]:
			raise Exception("SQL auto-commit is currently enabled!")

	@staticmethod
	def in_transaction():
		"""
		Returns a boolean True if inside a MySQL Transaction (which happens immediately after most SQL statements, including SELECT.
		"""
		query_result = frappe.db.sql("SELECT @@in_transaction AS in_transaction;", as_dict=True)
		if query_result:
			return bool(query_result[0]['in_transaction'])
		return False

	@staticmethod
	def get_connection_id():
		"""
		Returns the current SQL connection identifier.
		This value should not change in the middle of a gunicorn thread's execution.
		"""
		query_result = frappe.db.sql("SELECT connection_id() AS connection_id;", as_dict=True)
		if query_result:
			return query_result[0]['connection_id']
		return None

	@staticmethod
	def get_sql_transaction_details(to_stdout=False) -> dict:
		"""
		NOTE: Requires granting a new privilege to the SQL User:  GRANT Process ON *.* TO 'user_name'@'%';`
		"""

		connection_id = SQLTransaction.get_connection_id()
		if not connection_id:
			raise ValueError("Critical Error: Unable to determine the current MySQL connection identifer.")

		query = "SELECT * FROM information_schema.innodb_trx WHERE trx_mysql_thread_id = %(connection_id)s;"
		query_result = frappe.db.sql(query,	values={"connection_id": connection_id}, as_dict=True)

		if not query_result:
			return {}

		# Enforce a single row.
		if len(query_result) > 1:
			raise Exception(f"ERROR: Found more then 1 row of 'information_schema.innodb_trx'.  {query_result}")

		query_result = query_result[0]

		# pylint: disable=pointless-string-statement
		"""
		{
			"trx_id": "421340439900664",
			"trx_state": "RUNNING",
			"trx_started": "2022-06-18 20:41:30",
			"trx_requested_lock_id": null,
			"trx_wait_started": null,
			"trx_weight": 0,
			"trx_query": "SELECT * FROM information_schema.innodb_trx WHERE trx_mysql_thread_id = 106650",
			"trx_operation_state": null,
			"trx_tables_in_use": 0,
			"trx_tables_locked": 0,
			"trx_lock_structs": 0,
			"trx_lock_memory_bytes": 1136,
			"trx_rows_locked": 0,
			"trx_rows_modified": 0,
			"trx_concurrency_tickets": 0,
			"trx_isolation_level": "REPEATABLE READ",
			"trx_unique_checks": 1,
			"trx_foreign_key_checks": 1,
			"trx_last_foreign_key_error": null,
			"trx_is_read_only": 0,
			"trx_autocommit_non_locking": 0,
		}
		"""

		query_result['connection_id'] = connection_id
		query_result.pop('trx_mysql_thread_id')  # A bit confusing that 'thread_id' is 'connection_id', so replacing that key-value pair.

		if to_stdout:
			print(json.dumps(query_result, indent=4, default=str))

		return query_result

	@staticmethod
	def exist_uncommitted_changes(to_stdout=False, error_on_true=False) -> bool:
		"""
		Returns a boolean True if MariaDB has uncommited -changes- to rows or schema.
		"""
		# After any SQL COMMIT, it's important to sleep for a moment!.  Otherwise, you're querying TRX data before the MySQL
		# server has had an opportunity to update itself.  And you'll get a false negative about Uncommitted Transactions.
		# https://stackoverflow.com/questions/34303079/how-do-i-determine-if-i-have-uncommitted-writes-in-a-mysql-transaction

		frappe.db.sql("SELECT SLEEP(0.5);")

		transaction_details = SQLTransaction.get_sql_transaction_details()
		if not transaction_details:
			return False

		if transaction_details['trx_rows_modified'] > 0:
			if error_on_true:
				raise Exception(f"Uncommitted SQL Transactions exist: {transaction_details}")
			if to_stdout:
				print(f"Uncommitted SQL Transactions exist: {transaction_details}")
			return True

		return False

	def show_commit_call_stack(self):
		frappe.show_callstack()

	@staticmethod
	def give_commit_advice():
		"""
		This function can give advice, when a frappe.db.commit() is called, but there is nothing to actually commit.
		"""
		if not SQLTransaction.exist_uncommitted_changes():
			print("---> Commit Advice: There is no uncommitted SQL Transaction, and no need to db.commit()")
			frappe.show_callstack()


	@staticmethod
	def show_processes():
		result = frappe.db.sql("SHOW PROCESSLIST;")
		print(result)
