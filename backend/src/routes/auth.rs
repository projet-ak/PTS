use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{issue_token, verify_password, CurrentUser};
use crate::error::{ApiError, ApiResult};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/me", get(me))
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub full_name: Option<String>,
    pub role: String,
    pub company_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
}

type UserRow = (
    Uuid,
    String,
    String,
    String,
    Option<String>,
    Option<Uuid>,
    bool,
    i32,
    Option<DateTime<Utc>>,
);

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let row: Option<UserRow> = sqlx::query_as(
        "SELECT id, username, password_hash, role::text, full_name, company_id, \
                is_active, failed_attempts, locked_until \
           FROM users WHERE lower(username) = lower($1)",
    )
    .bind(body.username.trim())
    .fetch_optional(&state.db)
    .await?;

    // Kullanici yoksa da parola yanlissa da ayni cevabi doneriz; aksi halde
    // hangi kullanici adlarinin var oldugu disaridan ogrenilebilir.
    let (
        id,
        username,
        password_hash,
        role,
        full_name,
        company_id,
        is_active,
        failed_attempts,
        locked_until,
    ) = row.ok_or(ApiError::InvalidCredentials)?;

    let now = Utc::now();

    // Kilit suresi dolmadiysa parolayi hic denemeyiz.
    if let Some(until) = locked_until {
        if until > now {
            let minutes = ((until - now).num_seconds() as f64 / 60.0).ceil() as i64;
            tracing::warn!(username = %username, minutes, "kilitli hesapta giris denemesi");
            return Err(ApiError::LockedOut { minutes });
        }
    }

    if !is_active {
        return Err(ApiError::InvalidCredentials);
    }

    if !verify_password(&body.password, &password_hash) {
        // Kilit suresi gecmisse sayac sifirdan baslar.
        let expired = locked_until.map(|u| u <= now).unwrap_or(true);
        let attempts = if expired { 1 } else { failed_attempts + 1 };

        if attempts >= state.config.login_max_attempts {
            let until = now + Duration::minutes(state.config.login_lock_minutes);

            sqlx::query(
                "UPDATE users SET failed_attempts = 0, locked_until = $2 WHERE id = $1",
            )
            .bind(id)
            .bind(until)
            .execute(&state.db)
            .await?;

            tracing::warn!(
                username = %username,
                attempts,
                "hesap kilitlendi"
            );

            return Err(ApiError::LockedOut {
                minutes: state.config.login_lock_minutes,
            });
        }

        sqlx::query(
            "UPDATE users SET failed_attempts = $2, locked_until = NULL WHERE id = $1",
        )
        .bind(id)
        .bind(attempts)
        .execute(&state.db)
        .await?;

        tracing::warn!(username = %username, attempts, "hatali parola");
        return Err(ApiError::InvalidCredentials);
    }

    let token = issue_token(id, &username, &role, &state.config.jwt_secret)?;

    // Basarili giris sayaci ve kilidi temizler.
    sqlx::query(
        "UPDATE users SET last_login = now(), failed_attempts = 0, locked_until = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(&state.db)
    .await?;

    tracing::info!(username = %username, "oturum acildi");

    Ok(Json(LoginResponse {
        token,
        user: UserInfo {
            id,
            username,
            full_name,
            role,
            company_id,
        },
    }))
}

/// Sayfa yenilendiginde tokenin hala gecerli oldugunu dogrular.
async fn me(State(state): State<AppState>, user: CurrentUser) -> ApiResult<Json<UserInfo>> {
    let row: Option<(Uuid, String, Option<String>, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, username, full_name, role::text, company_id \
           FROM users WHERE id = $1 AND is_active",
    )
    .bind(user.id)
    .fetch_optional(&state.db)
    .await?;

    let (id, username, full_name, role, company_id) = row.ok_or(ApiError::Unauthorized)?;

    Ok(Json(UserInfo {
        id,
        username,
        full_name,
        role,
        company_id,
    }))
}
