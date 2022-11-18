
module "iam-policy-view-own-access" {
  source = "./iam-policies"
  iam_policy_name        = "test_policy"
  iam_policy_description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowUserAccessToPolicy",
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ]
        Resource = "arn:aws:iam::710004563535:policy/*",
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      },
      {
        Sid = "AllowUserListOwnAccess",
        Effect = "",
        Action = [
          "iam:ListAttachedUserPolicies",
          "iam:ListUserPolicies",
          "iam:ListGroupsForUser"
        ]
        Resource = "arn:aws:iam::710004563535:policy/*",
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      },
    ]
  })
}

module "iam-policy-selfservice-MFA" {
  source = "./iam-policies"
  iam_policy_name        = "test_policy"
  iam_policy_description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowUserAccessToCreateDeleteTheirOwnVirtualMFADevices"
        Effect = "Allow"
        Action = [
          "iam:*VirtualMFADevice"
        ]
        Resource = "arn:aws:iam::710004563535:mfa/*"
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      },
      {
        Sid = "AllowUsersToEnableSyncDisableTheirOwnMFADevices"
        Effect = "Allow"
        Action = [
          "iam:EnableMFADevice",
          "iam:DeactivateMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = "arn:aws:iam::710004563535:user/*"
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      },
      {
        Sid = "AllowUsersToListVirtualMFADevices"
        Effect = "Allow"
        Action = [
          "iam:ListVirtualMFADevices"
        ]
        Resource = "arn:aws:iam::710004563535:mfa/*"
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      },
      {
        Sid = "AllowUsersToListUsersInConsole"
        Effect = "Allow"
        Action = [
          "iam:ListUsers"
        ]
        Resource = "arn:aws:iam::710004563535:user/*"
      },
      {
        Sid = "AllowUsersAllActionsForCredentials"
        Effect = "Allow"
        Action = [
          "iam:*LoginProfile",
          "iam:*AccessKey*",
          "iam:*SigningCertificate*"
        ]
        Resource = "arn:aws:iam::710004563535:user/*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:*ChangePassword"
        ]
        Resource = "arn:aws:iam::477275408388:user/*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy"
        ]
        Resource = "arn:aws:iam::477275408388:*"
      },
      {
        Sid = "AllowUsersToSeeStatsOnIAMConsoleDashboard"
        Effect = "Allow"
        Action = [
          "iam:GetAccount*",
          "iam:ListAccount*"
        ]
        Resource = "arn:aws:iam::477275408388:*"
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      },
      {
        Sid = "GetCurrentUserGroups"
        Effect = "Allow"
        Action = [
          "iam:ListGroupsForUser"
        ]
        Resource = "arn:aws:iam::477275408388:*",
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      },
      {
        Sid = "GetAccountAlias"
        Effect = "Allow"
        Action = [
          "iam:ListAccountAliases"
        ]
        Resource = "*",
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      }
    ]
  })
}

module "iam-policy-selfservice-NoMFA" {
  source = "./iam-policies"
  iam_policy_name        = "iam-policy-access-selfservice-NoMFA"
  iam_policy_description = "Permissions for a user to assume the ReadOnly role, as long as they logged in with MFA."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowUsersToCreateDeleteTheirOwnVirtualMFADevices"
        Effect = "Allow"
        Action = [
          "iam:*VirtualMFADevice"
        ]
        Resource = "arn:aws:iam::477275408388:mfa/*" #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
      },
      {
        Sid = "AllowUsersToEnableSyncDisableTheirOwnMFADevices"
        Effect = "Allow"
        Action = [
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = "arn:aws:iam::477275408388:user/*" #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
      },
      {
        Sid = "AllowUsersToListVirtualMFADevices"
        Effect = "Allow"
        Action = [
          "iam:ListVirtualMFADevices"
        ]
        Resource = "arn:aws:iam::477275408388:mfa/*" #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
      },
      {
        Sid = "AllowUsersToListUsersInConsole"
        Effect = "Allow"
        Action = [
          "iam:ListUsers"
        ]
        Resource = "arn:aws:iam::477275408388:user/*" #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
      },
      {
        Sid = "AllowUsersAllActionsForCredentials"
        Effect = "Allow"
        Action = [
          "iam:*LoginProfile",
          "iam:*AccessKey*",
          "iam:*SigningCertificate*"
        ]
        Resource = "arn:aws:iam::477275408388:user/*" #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
      },
      {
        Action = [
          "iam:ChangePassword"
        ]
        Effect = "Allow"
        Resource = "arn:aws:iam::477275408388:user/*" #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
      },
      {
        Action = [
          "iam:GetAccountPasswordPolicy"
        ]
        Effect = "Allow"
        Resource = "arn:aws:iam::477275408388:*" #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
      },
      {
        sid = "AllowUsersToSeeStatsOnIAMConsoleDashboard"
        Action = [
          "iam:GetAccount*",
          "iam:ListAccount*"
        ]
        Effect = "Allow"
        Resource = "arn:aws:iam::477275408388:*" #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
      }
    ]
  })
}

module "iam-policy-access-readonly" {
  source = "./iam-policies"
  iam_policy_name        = "iam-policy-access-readonly"
  iam_policy_description = "Permissions for a user to assume the ReadOnly role, as long as they logged in with MFA."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "ReadOnly"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Resource = ["arn:aws:iam::710004563535:role/ReadOnly"] #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      }
    ]
  })
}

module "iam-policy-access-maintainer" {
  source = "./iam-policies"
  iam_policy_name        = "iam-policy-access-maintainer"
  iam_policy_description = "Permissions for a user to assume the Maintainer role, as long as they logged in with MFA."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "ReadOnly"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Resource = ["arn:aws:iam::710004563535:role/Maintainer"] #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      }
    ]
  })
}

module "iam-policy-access-fulladmin" {
  source = "./iam-policies"
  iam_policy_name        = "iam-policy-access-fulladmin"
  iam_policy_description = "Permissions for a user to assume the Full Admin role, as long as they logged in with MFA."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "FullAdmin"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Resource = ["arn:aws:iam::710004563535:role/FullAdmin"] #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      }
    ]
  })
}

############## IAM Roles
module "iam-role-readonly" {
  source = "./iam-roles"
  iam_role_name = "iam-role-read-only"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "FullAdmin"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Resource = ["arn:aws:iam::710004563535:role/iam-role-read-only"] #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      }
    ]
  })
}

module "iam-role-maintainer" {
  source = "./iam-roles"
  iam_role_name = "iam-role-read-only"
  iam_role_description = "This role has the AWS Managed Policy ReadOnlyAccess attached."
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "FullAdmin"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Resource = ["arn:aws:iam::710004563535:role/iam-role-maintainer"] #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      }
    ]
  })
}

module "iam-role-fulladmin" {
  source = "./iam-roles"
  iam_role_name = "iam-role-read-only"
  iam_role_description = "This role has the AWS Managed Policy AdministratorAccess attached."
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "FullAdmin"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Resource = ["arn:aws:iam::710004563535:role/iam-role-fulladmin"] #"arn:aws:iam::710004563535:policy/USER_${aws:username}", TBD
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      }
    ]
  })
}

################## IAM Roles to Policies attachment
module "iam-policies-roles-readonly" {
  source = "./iam-policies-roles-attachment"
  iam_role_name = module.iam-role-readonly.iam_role_name
  iam_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

module "iam-policies-roles-maintainer" {
  source = "./iam-policies-roles-attachment"
  iam_role_name = module.iam-role-maintainer.iam_role_name
  iam_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

module "iam-policies-roles-fulladmin" {
  source = "./iam-policies-roles-attachment"
  iam_role_name = module.iam-role-fulladmin.iam_role_name
  iam_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
} 

################## IAM Groups 
module "iam-group-selfservice" {
  source = "./iam-groups"
  iam_group_name = "SelfService-${var.env}"
}

module "iam-group-readonly" {
  source = "./iam-groups"
  iam_group_name = "SelfService-${var.env}"
}

module "iam-group-maintainer" {
  source = "./iam-groups"
  iam_group_name = "SelfService-${var.env}"
}

module "iam-group-fulladmin" {
  source = "./iam-groups"
  iam_group_name = "SelfService-${var.env}"
}

################## IAM Groups Attachments
module "iam-policies-groups-selfservice-MFA" {
  source = "./iam-policies-groups-attachment"
  iam_group_name = module.iam-group-selfservice.iam_group_name
  iam_policy_arn = module.iam-policy-selfservice-MFA.iam_policy_arn
}

module "iam-policies-groups-selfservice-view-own-access" {
  source = "./iam-policies-groups-attachment"
  iam_group_name = module.iam-group-selfservice.iam_group_name
  iam_policy_arn = module.iam-policy-view-own-access.iam_policy_arn
}

module "iam-policies-groups-ReadOnly" {
  source = "./iam-policies-groups-attachment"
  iam_group_name = module.iam-group-readonly.iam_group_name
  iam_policy_arn = module.iam-policy-access-readonly.iam_policy_arn
}

module "iam-policies-groups-maintainer" {
  source = "./iam-policies-groups-attachment"
  iam_group_name = module.iam-group-maintainer.iam_group_name
  iam_policy_arn = module.iam-policy-access-maintainer.iam_policy_arn
}

module "iam-policies-groups-fulladmin" {
  source = "./iam-policies-groups-attachment"
  iam_group_name = module.iam-group-fulladmin.iam_group_name
  iam_policy_arn = module.iam-policy-access-fulladmin.iam_policy_arn
}

############## IAM Users
module "iam-policy-access-readonly-role" {
  source = "./iam-users"
  iam_user = "jonathan"
  tag_use_case = "human"
}