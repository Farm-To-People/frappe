
# CLI USAGE
#
# ./env/bin/pytest --disable-pytest-warnings apps/frappe/frappe/database/test_datahenge.py
#

import frappe
from frappe.database.datahenge import SQLTransaction

SITE_NAME = 'testerp.farmtopeople.com'
SITES_PATH = '/home/sysop/clients/farm_to_people/v13_dev/mybench/sites'

def test_basic():
	assert "foo".upper() == "FOO"

def test_autocommit():
	frappe.init(site=SITE_NAME, sites_path=SITES_PATH)
	SQLTransaction.err_on_autocommit()

def test_not_in_transaction():
	frappe.init(site=SITE_NAME, sites_path=SITES_PATH)
	frappe.db.commit()
	assert SQLTransaction.in_transaction() == 0

def test_in_transaction():
	frappe.init(site=SITE_NAME, sites_path=SITES_PATH)
	frappe.db.commit()
	frappe.get_list("Item")
	assert SQLTransaction.in_transaction() == 1

def test_commits_1():
	frappe.init(site=SITE_NAME, sites_path=SITES_PATH)
	frappe.db.commit()
	frappe.get_list("Item")
	assert SQLTransaction.exist_uncommitted_changes() is False

def test_commits_2():
	frappe.init(site=SITE_NAME, sites_path=SITES_PATH)
	frappe.db.sql("SET AUTOCOMMIT=0;")
	frappe.db.commit()
	assert SQLTransaction.exist_uncommitted_changes() is False  # first test

	# customers = frappe.get_list("Customer", pluck='name')
	# first_customer_name = customers[0]
	first_customer_name = 'CUST-0000007'

	# Change the value of the comments to 'Red':
	statement = """ UPDATE `tabCustomer` SET `_comments` = 'Red'
	WHERE `name` = %(customer_name)s """
	frappe.db.sql(statement, values={'customer_name': first_customer_name})
	frappe.db.commit()
	frappe.db.sql("SELECT SLEEP(2);")

	statement = """ UPDATE `tabCustomer` SET `_comments` = CASE
	WHEN `_comments` = 'Red' THEN 'Blue'
	WHEN `_comments` = 'Blue' THEN 'Red'
	ELSE 'Yellow'
	END 
	WHERE `name` = %(customer_name)s """

	frappe.db.sql(statement, values={'customer_name': first_customer_name})

	assert SQLTransaction.exist_uncommitted_changes(to_stdout=False) is True  # second test
	frappe.db.commit()
	assert SQLTransaction.exist_uncommitted_changes(to_stdout=False) is False # third test

"""
def test_commits_3():
	frappe.init(site=SITE_NAME, sites_path=SITES_PATH)
	frappe.db.commit()

	doc_request_log = frappe.new_doc("API Request Log")
	doc_request_log.request_method = 'PUT'
	doc_request_log.local_endpoint = 'pytest_datahenge_sql_transactions'
	doc_request_log.payload = "test_commits_4"
	assert SQLTransaction.exist_uncommitted_changes() == 0
	doc_request_log.save(ignore_permissions=True)  # save does NOT implicitly commit a SQL Transaction.
	assert SQLTransaction.exist_uncommitted_changes() == 1
	frappe.db.commit()
	assert SQLTransaction.exist_uncommitted_changes() == 0
"""
