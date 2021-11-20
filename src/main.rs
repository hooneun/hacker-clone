#[macro_use]
extern crate diesel;
pub mod models;
pub mod schema;

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};

use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;

use models::{LoginUser, NewUser, User};

fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    PgConnection::establish(&database_url).expect(&format!("Error connection to {}", database_url))
}

#[derive(Serialize)]
struct Post {
    title: String,
    link: String,
    author: String,
}

#[derive(Debug, Deserialize)]
struct Submission {
    title: String,
    link: String,
}

async fn process_signup(data: web::Form<NewUser>) -> impl Responder {
    use schema::users;

    let connection = establish_connection();

    diesel::insert_into(users::table)
        .values(&*data)
        .get_result::<User>(&connection)
        .expect("Error registering user.");

    println!("{:?}", data);
    HttpResponse::Ok().body(format!("Successfully saved user: {}", data.username))
}

async fn index(tera: web::Data<Tera>) -> impl Responder {
    let mut data = Context::new();

    let posts = [
        Post {
            title: String::from("This is the first link"),
            link: String::from("https://example.com"),
            author: String::from("Bob"),
        },
        Post {
            title: String::from("This second link"),
            link: String::from("https://example.com"),
            author: String::from("Alice"),
        },
    ];

    data.insert("title", "Hacker Clone");
    data.insert("posts", &posts);

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

    if let Some(id) = id.identity() {
        return HttpResponse::Ok().body("Already logged in");
    }

    let rendered = tera.render("login.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn logout(id: Identity) -> impl Responder {
    id.forget();
    HttpResponse::Ok().body("Logged out")
}

async fn process_login(data: web::Form<LoginUser>, id: Identity) -> impl Responder {
    use schema::users::dsl::{username, users};

    let connection = establish_connection();
    let user = users
        .filter(username.eq(&data.username))
        .first::<User>(&connection);

    match user {
        Ok(u) => {
            if u.password == data.password {
                let session_token = String::from(u.username);
                id.remember(session_token);
                println!("{:?}", data);
                HttpResponse::Ok().body(format!("Logged in: {}", data.username))
            } else {
                HttpResponse::Ok().body("Password is incorrect.")
            }
        }
        Err(e) => {
            println!("{:?}", e);
            HttpResponse::Ok().body("User doesnt't exist.")
        }
    }
}

async fn submission(tera: web::Data<Tera>) -> impl Responder {
    let mut data = Context::new();
    data.insert("title", "Submit a Post");

    let rendered = tera.render("submission.html", &data).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn process_submission(data: web::Form<Submission>) -> impl Responder {
    println!("{:?}", data);
    HttpResponse::Ok().body(format!("Posted submission: {}", data.title))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let tera = Tera::new("templates/**/*").unwrap();
    HttpServer::new(move || {
        App::new()
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .secure(false),
            ))
            .data(tera.clone())
            .route("/", web::get().to(index))
            .route("/signup", web::get().to(signup))
            .route("/signup", web::post().to(process_signup))
            .route("/login", web::get().to(login))
            .route("/login", web::post().to(process_login))
            .route("/logout", web::post().to(logout))
            .route("/submission", web::get().to(submission))
            .route("/submission", web::post().to(process_submission))
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
