import yaml


ATTACHMENT_INSTRUCTIONS = """
Find attached policies to users on the javascript functions and return result in desired format.
First you need to find where policies were attached to users, search code for following patterns: 
  1. devkit/database <db|database>.collection(\"user\").<updateOne|updateMany|insertOne|insertMany> 
and relevant argument should include \"policies:[<policyids>]\" 
  2. devkit/auth <Auth|auth>.policy.attach(<userid>, <policyid>) 
  3. pure http call post request to the passport/user/<userid>/policy/<policyid>, with libraries like axios, fetch, etc. 
When you identified this kind of policy attachment, follow the references to determine where policies were defined. 
Definition could come from other spica functions, and imports at the top of the file with @spica-fn/<fn-name> format.
They could be \"process.env.<ENVIRONMENT_NAME>\", put name of them to the result if so, 
and also they could be hardcoded \"POLICY_ID\", put id of them to the result if so. 
Use the Grep, Glob and Read tools to search the function files.
Find code with Grep, using short single-line patterns such as identifiers or call names, then Read
only the lines around a match. Read may show just part of a long file, so do not rely on it to find code.
Do not repeat a search whose result you already have.
For every function id, use the function_id from the file listing, never the file name or the function name.
Return attachment object including function id and matched code where the policy was attached,
definition object including function id and matched code where the policy was defined,
and policy_id and/or policy_name found.
"""

ATTACHMENT_INPUT = "Search the project's functions for policy attachments."

BUCKET_ACL_INSTRUCTIONS = """
Evaluate both the read and write bucket ACL rules for row-level security.

`auth.key` and `auth.attributes.*` are set by administrators and server code. A user
cannot change their own, so a condition on an API key or on a role such as admin,
maintainer or support is a trusted identity check, never a bypass.

For each rule, set row_level_security_status to exactly one of:
- applied: every allowed access path either requires a unique request-owner value
  (auth._id, auth.username, or another unique auth field) to equal a target document
  field, or is restricted to trusted identities as described above.
- applied_but_in_risk: an owner-to-document comparison exists, but it uses a value shared
  by many users (such as a department or tenant), or another path opens access through a
  condition on the document alone (such as `document.shared == true`).
- not_applied: no owner comparison or trusted identity check restricts access, or access
  can be allowed unconditionally, such as with `|| true==true`.

Set includes_sensitive_information to True when the bucket title and/or schema
fields indicate personal or sensitive data, such as Users, Customers for titles,
and msisdn, email, password, address, identity, for fields. Set it to False
for operational/configuration data, such as Maintenance, Status, or
Configuration for titles and fields like status, version, or in_use etc.

Each reason is one short sentence of at most 15 words, in plain words, for a developer who
knows the bucket. Start every reason with "Any user with this policy". If a condition
limits who, add it next, such as "in the same department" or "older than 20", only when
the ACL really has one. Then finish with what they can do and to which documents, such as
"can read every document" or "can write any document". Do not quote the ACL expression.
Examples: "Any user with this policy can read every document." / "Any user with this
policy can write any document." / "Any user with this policy in the same department can
read any document."
"""


def bucket_acl_input(bucket):
    return f"Bucket schema:\n{yaml.safe_dump(bucket, sort_keys=False)}"
