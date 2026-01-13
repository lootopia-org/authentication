#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Public,
    Authenticated,
    SelfOnly,
    SelfOrAdmin,
    Admin,
}

pub struct RbacLayer;

impl RbacLayer {
    pub fn get_permission(method: &str) -> Permission {
        match method {
            "authentication.AuthenticationService/Register" => Permission::Public,
            "authentication.AuthenticationService/Login" => Permission::Public,
            "authentication.AuthenticationService/ResetPassword" => Permission::Public,
            "authentication.AuthenticationService/RefreshToken" => Permission::Public,

            "authentication.AuthenticationService/Logout" => Permission::Authenticated,
            "authentication.AuthenticationService/VerifyToken" => Permission::Authenticated,

            "authentication.AuthenticationService/UpdateUserEmail" => Permission::SelfOrAdmin,
            "authentication.AuthenticationService/ChangePassword" => Permission::SelfOnly,
            "authentication.AuthenticationService/DeleteUser" => Permission::SelfOrAdmin,

            "authentication.AuthenticationService/SendEmailVerification" => Permission::SelfOnly,
            "authentication.AuthenticationService/VerifyEmail" => Permission::SelfOnly,

            "authentication.AuthenticationService/AssignRole" => Permission::Admin,
            "authentication.AuthenticationService/RemoveRole" => Permission::Admin,
            "authentication.AuthenticationService/GetUserRoles" => Permission::SelfOrAdmin,
            "authentication.AuthenticationService/GetAuthFactors" => Permission::SelfOnly,
            "authentication.AuthenticationService/UpdateAuthFactors" => Permission::SelfOnly,

            _ => Permission::Authenticated,
        }
    }
}
