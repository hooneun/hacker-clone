#[macro_use]
extern crate diesel;
pub mod models;
pub mod schema;

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use tera::{Context, Tera};

use actix_web::middleware::Logger;
use argonautica::Verifier;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use dotenv::dotenv;

use models::{Comment, LoginUser, NewComment, NewPost, NewUser, Post, User};

type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Debug)]
enum ServerError {
    ArgonauticError,
    DieselError,
    EnvironmentError,
    R2D2Error,
    UserError(String),
}

impl From<argonautica::Error> for ServerError {
    fn from(_: argonautica::Error) -> ServerError {
        ServerError::ArgonauticError
    }
}

impl From<std::env::VarError> for ServerError {
    fn from(_: std::env::VarError) -> ServerError {
        ServerError::EnvironmentError
    }
}

impl From<r2d2::Error> for ServerError {
    fn from(_: r2d2::Error) -> ServerError {
        ServerError::R2D2Error
    }
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Test")
    }
}

impl From<diesel::result::Error> for ServerError {
    fn from(err: diesel::result::Error) -> ServerError {
        match err {
            diesel::result::Error::NotFound => {
                log::error!("{:?}", err);
                ServerError::UserError("Username not found.".to_string())
            }
            _ => ServerError::DieselError,
        }
    }
}

impl actix_web::error::ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServerError::ArgonauticError => {
                HttpResponse::InternalServerError().json("Argonautica Error.")
            }
            ServerError::DieselError => HttpResponse::InternalServerError().json("Diesel Error."),
            ServerError::EnvironmentError => {
                HttpResponse::InternalServerError().json("Environment Error.")
            }
            ServerError::R2D2Error => HttpResponse::InternalServerError().json("R2d2 Error."),
            ServerError::UserError(data) => HttpResponse::InternalServerError().json(data),
        }
    }
}

//fn establish_connection() -> PgConnection {
//    dotenv().ok();
//
//    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
//
//    PgConnection::establish(&database_url).expect(&format!("Error connection to {}", database_url))
//}

#[derive(Debug, Deserialize)]
struct Submission {
    title: String,
    link: String,
}

#[derive(Deserialize)]
struct CommentForm {
    comment: String,
}

async fn process_signup(data: web::Form<NewUser>, pool: web::Data<Pool>) -> impl Responder {
    use schema::users;

    let connection = pool.get().unwrap();

    let new_user = NewUser::new(
        data.username.clone(),
        data.email.clone(),
        data.password.clone(),
    );

    diesel::insert_into(users::table)
        .values(&new_user)
        .get_result::<User>(&connection)
        .expect("Error registering user.");

    println!("{:?}", data);
    HttpResponse::Ok().body(format!("Successfully saved user: {}", data.username))
}

async fn index(tera: web::Data<Tera>, pool: web::Data<Pool>) -> impl Responder {
    use schema::posts::dsl::posts;
    use schema::users::dsl::users;

    let connection = pool.get().unwrap();
    let all_posts: Vec<(Post, User)> = posts
        .inner_join(users)
        .load(&connection)
        .expect("Error retrieving all posts");

    let mut data = Context::new();

    data.insert("title", "Hacker Clone");
    data.insert("posts_users", &all_posts);

    let rendered = tera.render("index.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn signup(tera: web::Data<Tera>) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Sign up");

    let rendered = tera.render("signup.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn login(tera: web::Data<Tera>, id: Identity) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Login");

    if let Some(_id) = id.identity() {
        return HttpResponse::Ok().body("Already logged in");
    }

    let rendered = tera.render("login.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn logout(id: Identity) -> impl Responder {
    id.forget();
    HttpResponse::Ok().body("Logged out")
}

async fn process_login(
    data: web::Form<LoginUser>,
    pool: web::Data<Pool>,
    id: Identity,
) -> Result<HttpResponse, ServerError> {
    use schema::users::dsl::{username, users};

    let connection = pool.get()?;
    let user = users
        .filter(username.eq(&data.username))
        .first::<User>(&connection)?;

    dotenv().ok();
    let secret = std::env::var("SECRET_KEY")?;

    let valid = Verifier::default()
        .with_hash(user.password)
        .with_password(data.password.clone())
        .with_secret_key(secret)
        .verify()?;

    if valid {
        let session_token = String::from(user.username);
        id.remember(session_token);
        Ok(HttpResponse::Ok().body(format!("Logged in: {}", data.username)))
    } else {
        Ok(HttpResponse::Ok().body("Password is incorrect."))
    }
}

async fn submission(tera: web::Data<Tera>, id: Identity) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Submit a Post");

    if let Some(_id) = id.identity() {
        let rendered = tera.render("submission.html", &data).unwrap();
        return HttpResponse::Ok().body(rendered);
    }

    HttpResponse::Unauthorized().body("User not logged in")
}

async fn process_submission(
    data: web::Form<Submission>,
    pool: web::Data<Pool>,
    id: Identity,
) -> impl Responder {
    if let Some(id) = id.identity() {
        use schema::users::dsl::{username, users};

        let connection = pool.get().unwrap();
        let user: Result<User, diesel::result::Error> =
            users.filter(username.eq(id)).first(&connection);

        match user {
            Ok(u) => {
                let new_post = NewPost::from_post_form(data.title.clone(), data.link.clone(), u.id);

                use schema::posts;

                diesel::insert_into(posts::table)
                    .values(&new_post)
                    .get_result::<Post>(&connection)
                    .expect("Error saving post.");

                return HttpResponse::Ok().body("Submitted.");
            }
            Err(e) => {
                println!("{:?}", e);
                return HttpResponse::Ok().body("Failed to find user.");
            }
        }
    }
    HttpResponse::Unauthorized().body("User not logged in")
}

async fn post_page(
    tera: web::Data<Tera>,
    id: Identity,
    pool: web::Data<Pool>,
    web::Path(post_id): web::Path<i32>,
) -> impl Responder {
    use schema::posts::dsl::posts;
    use schema::users::dsl::users;

    let connection = pool.get().unwrap();

    let post: Post = posts
        .find(post_id)
        .get_result(&connection)
        .expect("Failed to find post");

    let user: User = users
        .find(post.author)
        .get_result(&connection)
        .expect("Failed to find user.");

    let comments: Vec<(Comment, User)> = Comment::belonging_to(&post)
        .inner_join(users)
        .load(&connection)
        .expect("Failed to find comments.");

    let mut data = Context::new();
    data.insert("title", &format!("{} - HackerClone", post.title));
    data.insert("post", &post);
    data.insert("user", &user);
    data.insert("comments", &comments);

    if let Some(_id) = id.identity() {
        data.insert("logged_in", "true");
    } else {
        data.insert("logged_in", "false");
    }

    let rednered = tera.render("post.html", &data).unwrap();
    HttpResponse::Ok().body(rednered)
}

async fn comment(
    data: web::Form<CommentForm>,
    id: Identity,
    pool: web::Data<Pool>,
    web::Path(post_id): web::Path<i32>,
) -> impl Responder {
    if let Some(id) = id.identity() {
        use schema::posts::dsl::posts;
        use schema::users::dsl::{username, users};

        let connection = pool.get().unwrap();

        let post: Post = posts
            .find(post_id)
            .get_result(&connection)
            .expect("Failed to find post.");

        let user: Result<User, diesel::result::Error> =
            users.filter(username.eq(id)).first(&connection);

        match user {
            Ok(u) => {
                let parent_id = None;
                let new_comment = NewComment::new(data.comment.clone(), post.id, u.id, parent_id);

                use schema::comments;
                diesel::insert_into(comments::table)
                    .values(&new_comment)
                    .get_result::<Comment>(&connection)
                    .expect("Error saving comment.");

                return HttpResponse::Ok().body("Commented.");
            }
            Err(e) => {
                println!("{:?}", e);
                return HttpResponse::Ok().body("User not found.");
            }
        }
    }
    HttpResponse::Unauthorized().body("Not logged in.")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let tera = Tera::new("templates/**/*").unwrap();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create postgres pool.");

    //env_looger::init();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .secure(false),
            ))
            .data(tera.clone())
            .data(pool.clone())
            .route("/", web::get().to(index))
            .route("/signup", web::get().to(signup))
            .route("/signup", web::post().to(process_signup))
            .route("/login", web::get().to(login))
            .route("/login", web::post().to(process_login))
            .route("/logout", web::post().to(logout))
            .route("/submission", web::get().to(submission))
            .route("/submission", web::post().to(process_submission))
            .service(
                web::resource("/posts/{post_id}")
                    .route(web::get().to(post_page))
                    .route(web::post().to(comment)),
            )
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
