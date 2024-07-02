#!/bin/bash

# Function to check if the user has admin permissions
check_admin_permissions() {
    echo "Checking for admin permissions..."

    # Get the current user's ARN
    user_arn=$(aws sts get-caller-identity --query "Arn" --output text)
    account_id=$(aws sts get-caller-identity --query "Account" --output text)
    user_type="IAM"

    if [ -z "$user_arn" ]; then
        echo -e "Unable to determine the user ARN. ✖\n"
        return 1
    fi

    # Check if the current user is an SSO user
    if [[ "$user_arn" == arn:aws:sts::$account_id:assumed-role/* ]]; then
        user_type="SSO"
        role_name=$(echo "$user_arn" | cut -d '/' -f 2)
        echo -e "SSO user detected. Role: $role_name\n"
    fi

    # Check if the current user is the root user
    if [[ "$user_arn" == "arn:aws:iam::$account_id:root" ]]; then
        echo -e "The current user is the root user, which has admin permissions. ✔\n"
        return 0
    fi

    # Function to check policies for admin permissions
    check_policies() {
        policies=$1
        for policy in $(echo "$policies" | jq -r '.AttachedPolicies[] | @base64'); do
            policy_name=$(echo "$policy" | base64 --decode | jq -r '.PolicyName')
            policy_arn=$(echo "$policy" | base64 --decode | jq -r '.PolicyArn')

            if [[ "$policy_name" == *"AdministratorAccess"* || "$policy_arn" == *"arn:aws:iam::$account_id:policy/AdministratorAccess"* ]]; then
                echo -e "Admin permissions found: $policy_name ($policy_arn) ✔"
                return 0
            fi
        done
        return 1
    }

    if [ "$user_type" == "IAM" ]; then
        # Extract the username from the ARN
        user_name=$(echo "$user_arn" | cut -d '/' -f 2)

        # List attached policies to the user
        policies=$(aws iam list-attached-user-policies --user-name $user_name)
        check_policies "$policies"
        if [ $? -eq 0 ]; then
            echo -e "The user has admin permissions. ✔\n"
            return 0
        fi

        # Check inline policies if no managed admin policies found
        inline_policies=$(aws iam list-user-policies --user-name $user_name)

        admin_inline_policy_found=false
        for policy in $(echo "$inline_policies" | jq -r '.PolicyNames[]'); do
            policy_document=$(aws iam get-user-policy --user-name $user_name --policy-name $policy --query 'PolicyDocument.Statement' --output json)
            if echo $policy_document | jq -e '.[] | select(.Effect == "Allow" and .Action == "*" and .Resource == "*")' > /dev/null; then
                echo -e "Admin inline policy found: $policy ✔"
                admin_inline_policy_found=true
                break
            fi
        done

        if $admin_inline_policy_found; then
            echo -e "The user has admin permissions through inline policies. ✔\n"
            return 0
        fi

        # Check if user is part of any group with admin permissions
        groups=$(aws iam list-groups-for-user --user-name $user_name)
        admin_group_policy_found=false

        for group in $(echo "$groups" | jq -r '.Groups[] | @base64'); do
            group_name=$(echo "$group" | base64 --decode | jq -r '.GroupName')
            group_policies=$(aws iam list-attached-group-policies --group-name $group_name)

            if check_policies "$group_policies"; then
                admin_group_policy_found=true
                break
            fi

            group_inline_policies=$(aws iam list-group-policies --group-name $group_name)
            for policy in $(echo "$group_inline_policies" | jq -r '.PolicyNames[]'); do
                policy_document=$(aws iam get-group-policy --group-name $group_name --policy-name $policy --query 'PolicyDocument.Statement' --output json)
                if echo $policy_document | jq -e '.[] | select(.Effect == "Allow" and .Action == "*" and .Resource == "*")' > /dev/null; then
                    echo -e "Admin inline policy found in group: $group_name ($policy) ✔"
                    admin_group_policy_found=true
                    break 2
                fi
            done
        done

        if $admin_group_policy_found; then
            echo -e "The user has admin permissions through group policies. ✔\n"
            return 0
        fi
    else
        # For SSO users, check role policies
        role_policies=$(aws iam list-attached-role-policies --role-name $role_name)
        check_policies "$role_policies"
        if [ $? -eq 0 ]; then
            echo -e "The user has admin permissions through role policies. ✔\n"
            return 0
        fi

        # Check inline policies for the role
        inline_policies=$(aws iam list-role-policies --role-name $role_name)
        admin_inline_policy_found=false

        for policy in $(echo "$inline_policies" | jq -r '.PolicyNames[]'); do
            policy_document=$(aws iam get-role-policy --role-name $role_name --policy-name $policy --query 'PolicyDocument.Statement' --output json)
            if echo $policy_document | jq -e '.[] | select(.Effect == "Allow" and .Action == "*" and .Resource == "*")' > /dev/null; then
                echo -e "Admin inline policy found in role: $role_name ($policy) ✔"
                admin_inline_policy_found=true
                break
            fi
        done

        if $admin_inline_policy_found; then
            echo -e "The user has admin permissions through inline role policies. ✔\n"
            return 0
        fi
    fi

    echo -e "No admin permissions found for the user. ✖\n"
    return 1
}

# Function to check if CloudFormation is accessible
check_cloudformation_accessible() {
    echo "Checking if CloudFormation is accessible..."
    aws cloudformation describe-stacks --stack-name non-existent-stack > /dev/null 2>&1

    if [ $? -eq 254 ]; then
        echo -e "CloudFormation is accessible. ✔\n"
        return 0
    else
        echo -e "CloudFormation is not accessible or another error occurred. ✖\n"
        return 1
    fi
}

# Function to check if trusted service for CloudFormation StackSets is enabled
check_trusted_service() {
    echo "Checking if trusted service for CloudFormation StackSets is enabled in AWS Organizations..."
    trusted_service_enabled=$(aws organizations list-aws-service-access-for-organization --query 'EnabledServicePrincipals[?ServicePrincipal==`member.org.stacksets.cloudformation.amazonaws.com`]' --output text)

    if [ -n "$trusted_service_enabled" ]; then
        echo -e "Trusted service for CloudFormation StackSets is enabled. ✔\n"
        return 0
    else
        echo -e "Trusted service for CloudFormation StackSets is not enabled. ✖\n"
        return 1
    fi
}

echo -e "\n"

# Run the functions
check_admin_permissions
admin_check_result=$?

check_cloudformation_accessible
cloudformation_check_result=$?

check_trusted_service
trusted_service_check_result=$?

# Final check and message
if [ $admin_check_result -eq 0 ] && [ $cloudformation_check_result -eq 0 ] && [ $trusted_service_check_result -eq 0 ]; then
    echo -e "All checks passed, you should be able to proceed with deployment! ✔\n"
else
    echo -e "One or more checks failed, please address the issues and try again. ✖\n"
fi
