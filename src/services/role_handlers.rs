use crate::db::schema::*;
use crate::domain::*;
use crate::middleware::RequestExt;
use crate::models::{NewUserRole, Role};
use crate::services::auth_service::AuthService;
use crate::services::grpc::*;
use diesel::prelude::*;
use tonic::{Request, Response, Status};
use tracing::{debug, error, warn};

impl AuthService {
    pub async fn assign_role_to_user(
        &self,
        request: Request<AssignRoleRequest>,
    ) -> Result<Response<AssignRoleResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let req = request.into_inner();

        debug!(
            "Assign role request received from admin: {}",
            auth_ctx.user.id
        );


        let role = roles::table
            .filter(roles::name.eq(&req.role_name))
            .first::<Role>(&mut self.conn()?)
            .optional()
            .map_err(|e| {
                error!("Database error fetching role: {}", e);
                AuthError::Database(e).to_status()
            })?
            .ok_or_else(|| {
                warn!("Role not found: {}", req.role_name);
                AuthError::RoleNotFound(req.role_name.clone()).to_status()
            })?;

        let new_user_role = NewUserRole {
            user_id: auth_ctx.user.id,
            role_id: role.id,
        };

        diesel::insert_into(user_roles::table)
            .values(&new_user_role)
            .execute(&mut self.conn()?)
            .map_err(|e| {
                error!("Failed to assign role: {}", e);
                AuthError::Database(e).to_status()
            })?;

        Ok(Response::new(AssignRoleResponse {
            success: true,
            message: format!("Role '{}' assigned successfully", req.role_name),
        }))
    }

    pub async fn remove_role_from_user(
        &self,
        request: Request<RemoveRoleRequest>,
    ) -> Result<Response<RemoveRoleResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let req = request.into_inner();

        debug!(
            "Remove role request received from admin: {}",
            auth_ctx.user.id
        );

        let role = roles::table
            .filter(roles::name.eq(&req.role_name))
            .first::<Role>(&mut self.conn()?)
            .optional()
            .map_err(|e| {
                error!("Database error fetching role: {}", e);
                AuthError::Database(e).to_status()
            })?
            .ok_or_else(|| {
                warn!("Role not found: {}", req.role_name);
                AuthError::RoleNotFound(req.role_name.clone()).to_status()
            })?;

        diesel::delete(
            user_roles::table
                .filter(user_roles::user_id.eq(auth_ctx.user.id))
                .filter(user_roles::role_id.eq(role.id)),
        )
        .execute(&mut self.conn()?)
        .map_err(|e| {
            error!("Failed to remove role: {}", e);
            AuthError::Database(e).to_status()
        })?;

        Ok(Response::new(RemoveRoleResponse {
            success: true,
            message: format!("Role '{}' removed successfully", req.role_name),
        }))
    }

    pub async fn get_roles_for_user(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<GetUserRolesResponse>, Status> {
        let auth_ctx = request.auth()?;
        let role_names = auth_ctx.roles.clone();
        
        debug!(
            "Get user roles request for user {}",
            auth_ctx.user.id
        );

        Ok(Response::new(GetUserRolesResponse {
            success: true,
            message: "Roles retrieved successfully".to_string(),
            roles: role_names,
        }))
    }
}
