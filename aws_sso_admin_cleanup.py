import argparse
import boto3

def list_all(sso_admin_client, identitystore_client, instance_arn, permission_set_arn, account_id, identity_store_id, output_file=None):
    if account_id == "ALL":
        accounts = list_accounts_for_provisioned_permission_set(sso_admin_client, instance_arn, permission_set_arn)
    else:
        accounts = [account_id]

    results = []
    for acc in accounts:
        assignments = list_account_assignments(sso_admin_client, instance_arn, permission_set_arn, acc)
        results.extend(assignments)
    
    for assignment in results:
        principal_name = get_principal_name(identitystore_client, identity_store_id, assignment['PrincipalId'], assignment['PrincipalType'])
        ou_path = get_ou_path(assignment['AccountId'])
        output_string = f"Account: {assignment['AccountId']} (OU Path: {ou_path}), Principal Type: {assignment['PrincipalType']}, Principal ID: {assignment['PrincipalId']}, Principal Name: {principal_name}"
        
        if output_file:
            with open(output_file, 'a') as f:
                f.write(output_string + '\n')
        else:
            print(output_string)


   
def get_principal_name(identitystore_client, identity_store_id, principal_id, principal_type):
    if principal_type == "USER":
        response = identitystore_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=principal_id
        )
        return response['UserName']
    elif principal_type == "GROUP":
        response = identitystore_client.describe_group(
            IdentityStoreId=identity_store_id,
            GroupId=principal_id
        )
        return response['DisplayName']
    else:
        return "Unknown"
    

def get_ou_path(account_id):
    org_client = boto3.client('organizations')
    ou_path = []
    
    # Get parent of the account
    parent_details = org_client.list_parents(ChildId=account_id)
    if parent_details['Parents']:
        parent_id = parent_details['Parents'][0]['Id']
        parent_type = parent_details['Parents'][0]['Type']
    else:
        parent_id = None
        parent_type = None
    
    while parent_id and parent_type == 'ORGANIZATIONAL_UNIT':
        # Get OU details
        ou_details = org_client.describe_organizational_unit(OrganizationalUnitId=parent_id)
        ou_name = ou_details['OrganizationalUnit']['Name']
        ou_path.insert(0, ou_name)  # Add OU name to the beginning of the path
        
        # Get parent of the current OU
        parent_details = org_client.list_parents(ChildId=parent_id)
        if parent_details['Parents']:
            parent_id = parent_details['Parents'][0]['Id']
            parent_type = parent_details['Parents'][0]['Type']
        else:
            parent_id = None
            parent_type = None
    
    return "/".join(ou_path)


def get_permission_set_name(sso_admin_client, instance_arn, permission_set_arn):
    details = sso_admin_client.describe_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    )
    return details['PermissionSet']['Name']

def list_all_permission_sets_assignments(sso_admin_client, identitystore_client, instance_arn, account_id, identity_store_id, output_file=None):
    permission_sets = list_permission_sets_arns(sso_admin_client, instance_arn)

    if output_file: #clear the file
        with open(output_file, 'w') as f:
            pass

    for permission_set_arn in permission_sets:
        # Get the name of the permission set using the new function
        permission_set_name = get_permission_set_name(sso_admin_client, instance_arn, permission_set_arn)
        
        # Print the name as a header
        header = f"\nPermission Set: {permission_set_name} (ARN: {permission_set_arn})"
        if output_file:
            with open(output_file, 'a') as f:
                f.write(header + '\n')
        else:
            print(header)
        
        # List all assignments for the permission set
        list_all(sso_admin_client, identitystore_client, instance_arn, permission_set_arn, account_id, identity_store_id, output_file=output_file)


def list_permission_sets_arns(sso_admin_client, instance_arn):
    permission_sets = []
    paginator = sso_admin_client.get_paginator('list_permission_sets')
    for page in paginator.paginate(InstanceArn=instance_arn):
        permission_sets.extend(page['PermissionSets'])
    return permission_sets


def remove_all(sso_admin_client, instance_arn, permission_set_arn, account_id):
    if account_id == "ALL":
        accounts = list_accounts_for_provisioned_permission_set(sso_admin_client, instance_arn, permission_set_arn)
    else:
        accounts = [account_id]

    for acc in accounts:
        assignments = list_account_assignments(sso_admin_client, instance_arn, permission_set_arn, acc)
        for assignment in assignments:
            delete_account_assignment(sso_admin_client, instance_arn, permission_set_arn, acc, assignment['PrincipalType'], assignment['PrincipalId'])

def list_accounts_for_provisioned_permission_set(sso_admin_client, instance_arn, permission_set_arn):
    account_ids = []
    paginator = sso_admin_client.get_paginator('list_accounts_for_provisioned_permission_set')
    for page in paginator.paginate(InstanceArn=instance_arn, PermissionSetArn=permission_set_arn):
        account_ids.extend(page['AccountIds'])
    return account_ids

def list_account_assignments(sso_admin_client, instance_arn, permission_set_arn, account_id):
    assignments = []
    paginator = sso_admin_client.get_paginator('list_account_assignments')
    for page in paginator.paginate(InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=permission_set_arn):
        assignments.extend(page['AccountAssignments'])
    return assignments


def delete_account_assignment(sso_admin_client, instance_arn, permission_set_arn, account_id, principal_type, principal_id):
    sso_admin_client.delete_account_assignment(
        InstanceArn=instance_arn,
        AccountId=account_id,
        PermissionSetArn=permission_set_arn,
        PrincipalType=principal_type,
        PrincipalId=principal_id
    )

def list_permission_sets(sso_admin_client, instance_arn):
    paginator = sso_admin_client.get_paginator('list_permission_sets')
    for page in paginator.paginate(InstanceArn=instance_arn):
        for permission_set_arn in page['PermissionSets']:
            details = sso_admin_client.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            print(f"ARN: {permission_set_arn}, Name: {details['PermissionSet']['Name']}")

def get_identity_store_id(sso_admin_client, instance_arn):
    response = sso_admin_client.list_instances()
    for instance in response['Instances']:
        if instance['InstanceArn'] == instance_arn:
            return instance['IdentityStoreId']
    raise ValueError(f"No IdentityStoreId found for InstanceArn: {instance_arn}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS SSO Admin Permission Cleanup Tool using boto3")
    parser.add_argument("action", choices=["list-all", "remove-all", "list-permission-sets", "list-all-permission-sets-assignments"], help="Action to perform")
    parser.add_argument("--account-id", default=None, help="Account ID or 'ALL' for all accounts")
    parser.add_argument("--permission-set-arn", default=None, help="Permission Set ARN")
    parser.add_argument("--instance-arn", required=True, help="Instance ARN")
    parser.add_argument("-o", "--output", default=None, help="Output file path. If provided, results will be written to this file instead of stdout.")
   

    args = parser.parse_args()

    sso_admin_client = boto3.client('sso-admin')
    identitystore_client = boto3.client('identitystore')

    identity_store_id = get_identity_store_id(sso_admin_client, args.instance_arn)
    
    if args.action == "list-all":
        list_all(sso_admin_client, identitystore_client, args.instance_arn, args.permission_set_arn, args.account_id, identity_store_id, args.output)
    elif args.action == "remove-all":
        remove_all(sso_admin_client, args.instance_arn, args.permission_set_arn, args.account_id)
    elif args.action == "list-permission-sets":
        list_permission_sets(sso_admin_client, args.instance_arn)
    elif args.action == "list-all-permission-sets-assignments":
        list_all_permission_sets_assignments(sso_admin_client, identitystore_client, args.instance_arn, args.account_id, identity_store_id, output_file=args.output)
