# infrastructure-modules

TaxCycle-Xero's Terraform Infrastructure Modules

![Drag Racing](image.png)

# Motivation
Follows Terragrunt IaC code structure to keep infrastructure code DRY for multi-environment setups (dev/qa/staging/prod)
Holds IO Modules for infrastructure-live repo to use
Currently Terraform does not support single-repo well - hence the need for seperated module / live repos

# How to use

Install Terraform v1.3.1
https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli

Install Terragrunt v0.39.2
https://terragrunt.gruntwork.io/docs/getting-started/install/

# How to Update Modules

1. Follow Git Flow Protocol: https://danielkummer.github.io/git-flow-cheatsheet/
2. To add files to stage, run `git add <fileshere>`
3. tag your commits to allow versioning for future rollback 
    `git tag v0.0.x`
4. Commit your code with an appropriate message. Please follow this standard: https://www.freecodecamp.org/news/how-to-write-better-git-commit-messages/
5. Create a pull request from feature branch into develop - assign it to Infra Lead (Jonathan) for review
