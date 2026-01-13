use crate::services::auth_service::AuthService;
use crate::services::grpc::authentication_service_server::AuthenticationService;
use crate::services::grpc::*;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl AuthenticationService for AuthService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        self.register_user(request).await
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        self.login_user(request).await
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        self.logout_user(request).await
    }

    async fn refresh_token(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        self.refresh_access_token(request).await
    }

    async fn verify_token(
        &self,
        request: Request<VerifyTokenRequest>,
    ) -> Result<Response<VerifyTokenResponse>, Status> {
        self.verify_access_token(request).await
    }


    async fn update_user_email(
        &self,
        request: Request<UpdateUserEmailRequest>,
    ) -> Result<Response<UpdateUserEmailResponse>, Status> {
        self.update_user_email(request).await
    }

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>, Status> {
        self.change_user_password(request).await
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        self.delete_user_account(request).await
    }

    async fn send_email_verification(
        &self,
        request: Request<SendEmailVerificationRequest>,
    ) -> Result<Response<SendEmailVerificationResponse>, Status> {
        self.send_email_verification_code(request).await
    }

    async fn verify_email(
        &self,
        request: Request<VerifyEmailRequest>,
    ) -> Result<Response<VerifyEmailResponse>, Status> {
        self.verify_user_email(request).await
    }

    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResetPasswordResponse>, Status> {
        self.reset_user_password(request).await
    }

    async fn assign_role(
        &self,
        request: Request<AssignRoleRequest>,
    ) -> Result<Response<AssignRoleResponse>, Status> {
        self.assign_role_to_user(request).await
    }

    async fn remove_role(
        &self,
        request: Request<RemoveRoleRequest>,
    ) -> Result<Response<RemoveRoleResponse>, Status> {
        self.remove_role_from_user(request).await
    }

    async fn get_user_roles(
        &self,
        request: Request<GetUserRolesRequest>,
    ) -> Result<Response<GetUserRolesResponse>, Status> {
        self.get_roles_for_user(request).await
    }

    async fn get_auth_factors(
        &self,
        request: Request<GetAuthFactorsRequest>,
    ) -> Result<Response<GetAuthFactorsResponse>, Status> {
        self.get_auth_factors_for_user(request).await
    }

    async fn update_auth_factors(
        &self,
        request: Request<UpdateAuthFactorsRequest>,
    ) -> Result<Response<UpdateAuthFactorsResponse>, Status> {
        self.update_auth_factors_for_user(request).await
    }
}
