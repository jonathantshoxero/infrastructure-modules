
module "iam-policy-view-own-access" {
  source = "./iam-policies"
  iam_policy_name        = "view-own-access-dev"
  iam_policy_description = "My test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowUserAccessToPolicy"
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ]
        Resource = "arn:aws:iam::710004563535:policy/*"
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      },
      {
        Sid = "AllowUserListOwnAccess"
        Effect = "",
        Action = [
          "iam:ListAttachedUserPolicies",
          "iam:ListUserPolicies",
          "iam:ListGroupsForUser"
        ]
        Resource = "arn:aws:iam::710004563535:policy/*"
        Condition = {
            Bool = {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
      }
    ]
  })
}

module "iam-policy-selfservice-MFA" {
  source = "./iam-policies"
  iam_policy_name        = "selfservice-MFA-dev"
  iam_policy_description = "My test policy"

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
        Resource = "arn:aws:iam::477275408388:*"
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
        Resource = "*"
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
        Resource = "arn:aws:iam::477275408388:mfa/*"
      },
      {
        Sid = "AllowUsersToEnableSyncDisableTheirOwnMFADevices"
        Effect = "Allow"
        Action = [
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = "arn:aws:iam::477275408388:user/*"
      },
      {
        Sid = "AllowUsersToListVirtualMFADevices"
        Effect = "Allow"
        Action = [
          "iam:ListVirtualMFADevices"
        ]
        Resource = "arn:aws:iam::477275408388:mfa/*"
      },
      {
        Sid = "AllowUsersToListUsersInConsole"
        Effect = "Allow"
        Action = [
          "iam:ListUsers"
        ]
        Resource = "arn:aws:iam::477275408388:user/*"
      },
      {
        Sid = "AllowUsersAllActionsForCredentials"
        Effect = "Allow"
        Action = [
          "iam:*LoginProfile",
          "iam:*AccessKey*",
          "iam:*SigningCertificate*"
        ]
        Resource = "arn:aws:iam::477275408388:user/*"
      },
      {
        Action = [
          "iam:ChangePassword"
        ]
        Effect = "Allow"
        Resource = "arn:aws:iam::477275408388:user/*"
      },
      {
        Action = [
          "iam:GetAccountPasswordPolicy"
        ]
        Effect = "Allow"
        Resource = "arn:aws:iam::477275408388:*"
      },
      {
        sid = "AllowUsersToSeeStatsOnIAMConsoleDashboard"
        Action = [
          "iam:GetAccount*",
          "iam:ListAccount*"
        ]
        Effect = "Allow"
        Resource = "arn:aws:iam::477275408388:*"
      }
    ]
  })
}

module "iam-policy-access-readonly" {
  source = "./iam-policies"
  iam_policy_name        = "iam-policy-access-readonly"
  iam_policy_description = "Permissions for a user to assume the ReadOnly role, as long as they logged in with MFA."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "ReadOnly"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Resource = ["arn:aws:iam::710004563535:role/ReadOnly"] 
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

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "ReadOnly"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Resource = ["arn:aws:iam::710004563535:role/Maintainer"]
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

  # policy = jsonencode({
  #   Version = "2012-10-17"
  #   Statement = [
  #     {
  #       Sid = "FullAdmin"
  #       Action = [
  #         "sts:AssumeRole",
  #         "sts:TagSession"
  #       ]
  #       Resource = ["arn:aws:iam::710004563535:role/FullAdmin"]
  #       Condition = {
  #           Bool = {
  #               "aws:MultiFactorAuthPresent": "true"
  #           }
  #       }
  #     }
  #   ]
  # })

  policy = policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
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
        Effect = "Allow"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Principal = {
				  AWS = "arn:aws:iam::710004563535:user/jonathan.ho@xero.com"
        }
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
  iam_role_name = "iam-role-maintainer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "FullAdmin"
        Effect = "Allow"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Principal = {
				  AWS = "arn:aws:iam::710004563535:user/jonathan.ho@xero.com"
        }
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
  iam_role_name = "iam-role-fulladmin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "FullAdmin"
        Effect = "Allow"
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Principal = {
				  AWS = "arn:aws:iam::710004563535:user/jonathan.ho@xero.com"
        }
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
  iam_group_name = "readonly-${var.env}"
}

module "iam-group-maintainer" {
  source = "./iam-groups"
  iam_group_name = "maintainer-${var.env}"
}

module "iam-group-fulladmin" {
  source = "./iam-groups"
  iam_group_name = "fulladmin-${var.env}"
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