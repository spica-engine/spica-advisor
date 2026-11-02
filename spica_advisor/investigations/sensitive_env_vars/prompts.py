SENSITIVENESS_INSTRUCTIONS = """
Classify how sensitive the value of each environment variable is likely to be,
from its name. 

Set sensitiveness_level to exactly one of:
- high: the name indicates that holds sensitive information, such as secret, password,
  apikey, service_account, token, private_key.
- low: the name indicates non-sensitive configuration, such as username, env,
  config, public_url, log_level, timeout, region, or feature flags.
- low also covers names that only identify or point to something instead of holding
  a secret: ids, arns, account numbers, secret names, and paths or filenames of public
  material such as certificates.
- medium: the name might indicate sensitive information but not sure without knowing it's value or usage,
  such as client_key, public_key, connection_url(may contain credentials, may not).
  Actually it's the grey area between high and low sensitivity.

Write a very very short explanation of a few words for each, to their reason values.
"""


def sensitiveness_input(env_var_names):
    names = "\n".join(f"- {name}" for name in env_var_names)
    return f"Environment variable names:\n{names}"
