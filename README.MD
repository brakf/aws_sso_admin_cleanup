# AWS SSO Admin Permission Cleanup Tool

This tool is designed to help manage AWS SSO permissions using the `boto3` library. It provides functionalities like listing all permissions, removing all permissions, and more.
I build it as an extension to the existing CLI as it didn't really help me to cleanup permission assignments at scale on a large organization

## Prerequisites

- Python 3.x
- `boto3` library installed
- AWS credentials configured (either using `aws configure` or environment variables)

## Features

- List all permissions for a given account or all accounts.
- Remove all permissions for a given account or all accounts.
- List all permission sets.
- List all assignments for all permission sets.

## Usage

1. Clone the repository or download the script.
2. Navigate to the directory containing the script.
3. Run the script using the following command:

```
python3 aws_sso_admin_cleanup.py [ACTION] --instance-arn [INSTANCE_ARN] [OPTIONS]
```

### Parameters:

- `[ACTION]`: The action you want to perform. Choose from:
  - `list-all`
  - `remove-all`
  - `list-permission-sets`
  - `list-all-permission-sets-assignments`
  
- `[INSTANCE_ARN]`: The ARN of the SSO instance.

### Options:

- `--account-id [ACCOUNT_ID]`: The AWS account ID or 'ALL' for all accounts. Default is `None`.
- `--permission-set-arn [PERMISSION_SET_ARN]`: The ARN of the permission set. Default is `None`.
- `-o` or `--output [OUTPUT_FILE_PATH]`: The path to the output file. If provided, results will be written to this file instead of stdout.

## Examples:

To list all permission sets assignments for all accounts:

```
python3 aws_sso_admin_cleanup.py list-all-permission-sets-assignments --account-id ALL --instance-arn arn:aws:sso:::instance/ssoins-1234567890abc -o out.txt
```