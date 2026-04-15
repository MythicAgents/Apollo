package sentinel.authz

default allow = false

allow if {
  input.action == "download"
  input.resource == "github"
  input.user.role == "employee"
}

deny_reason[msg] if {
  input.action == "download"
  input.resource == "github"
  input.user.role == "contractor"
  msg := "Contractors are not allowed to download from GitHub."
}
