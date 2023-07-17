#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/serializer/rapidjson.h>
#include <rapidjson/document.h>
#include <sqlite3.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace Pistache;
using namespace Pistache::Rest;
using namespace rapidjson;

// Database connection
class Database {
public:
    Database(const std::string& dbPath)
        : db(nullptr)
    {
        int rc = sqlite3_open(dbPath.c_str(), &db);
	if (rc) {
            std::cerr << "Error opening SQLite database: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            db = nullptr;
        } else {
            createTables();
        }
    }

    ~Database()
    {
        if (db) {
            sqlite3_close(db);
        }
    }

    bool isValid() const { return db != nullptr; }

    void createTables()
    {
        executeQuery("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, password TEXT)");
        executeQuery("CREATE TABLE IF NOT EXISTS bookmarks (id INTEGER PRIMARY KEY, link TEXT, is_public INTEGER, user_id INTEGER)");
    }

    void executeQuery(const std::string& query)
    {
        char* errMsg = nullptr;
        int rc = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "Error executing query: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
    }

    sqlite3* getDB() const { return db; }

private:
    sqlite3* db;
};

// User entity
struct User {
    int id;
    std::string email;
    std::string password;
};

// Bookmark entity
struct Bookmark {
    int id;
    std::string link;
    bool isPublic;
    int userId;
};

// API handler
class BookmarkHandler {
public:
    BookmarkHandler(Database& database)
        : db(database)
    {
    }

    void createUser(const Rest::Request& request, Http::ResponseWriter response)
    {
        const auto body = request.body();
        Document document;
        document.Parse(body.c_str());

        if (!document.HasMember("email") || !document.HasMember("password")) {
            response.send(Http::Code::Bad_Request, "Invalid request body\n");
	    return;
        }

        std::string email = document["email"].GetString();
        std::string password = document["password"].GetString();

        if (getUserByEmail(email)) {
            response.send(Http::Code::Conflict, "User already exists\n");
            return;
        }

	std::string query = "INSERT INTO users (email, password) VALUES ('" + email + "', '" + password + "')";
        db.executeQuery(query);

        response.send(Http::Code::Created, "User created\n");
    }

    void loginUser(const Rest::Request& request, Http::ResponseWriter response)
    {
        const auto body = request.body();
        Document document;
        document.Parse(body.c_str());

        if (!document.HasMember("email") || !document.HasMember("password")) {
            response.send(Http::Code::Bad_Request, "Invalid request body\n");
            return;
        }

        std::string email = document["email"].GetString();
        std::string password = document["password"].GetString();

        User* user = getUserByEmail(email);
        if (!user || user->password != password) {
            response.send(Http::Code::Unauthorized, "Invalid email or password\n");
            return;
        }

	// TO DO generate unique tokens
        std::string token = std::to_string(user->id); // Taking token as user id for now

        response.headers().add<Http::Header::ContentType>(MIME(Application, Json));
        response.send(Http::Code::Ok, "{\"token\": \"" + token + "\"}\n");
    }

    void getUserBookmarks(const Rest::Request& request, Http::ResponseWriter response)
    {
        // Get user ID from token
        int userId = getUserIdFromToken(request);
        if (userId == -1) {
            response.send(Http::Code::Unauthorized, "Invalid token\n");
            return;
        }

        std::vector<Bookmark> bookmarks = getBookmarksByUserId(userId);
        sendJsonResponse(response, bookmarks);
    }

    void getPublicBookmarks(const Rest::Request& request, Http::ResponseWriter response)
    {
        std::vector<Bookmark> bookmarks = getPublicBookmarks();
        sendJsonResponse(response, bookmarks);
    }

    void addBookmark(const Rest::Request& request, Http::ResponseWriter response)
    {
        // Get user ID from token
        int userId = getUserIdFromToken(request);
        if (userId == -1) {
            response.send(Http::Code::Unauthorized, "Invalid token\n");
            return;
        }

        const auto body = request.body();
        Document document;
        document.Parse(body.c_str());

        if (!document.HasMember("link") || !document.HasMember("is_public")) {
            response.send(Http::Code::Bad_Request, "Invalid request body\n");
            return;
        }

        std::string link = document["link"].GetString();
        bool isPublic = document["is_public"].GetBool();

        std::string query = "INSERT INTO bookmarks (link, is_public, user_id) VALUES ('" + link + "', " + std::to_string(isPublic) + ", " + std::to_string(userId) + ")";
        db.executeQuery(query);

        response.send(Http::Code::Created, "Bookmark added\n");
    }

    void removeBookmark(const Rest::Request& request, Http::ResponseWriter response)
    {
        // Get user ID from token
        int userId = getUserIdFromToken(request);
        if (userId == -1) {
            response.send(Http::Code::Unauthorized, "Invalid token\n");
            return;
        }

        int bookmarkId = std::stoi(request.param(":bookmarkId").as<std::string>());

        Bookmark* bookmark = getBookmarkById(bookmarkId);
        if (!bookmark || bookmark->userId != userId) {
            response.send(Http::Code::Forbidden, "You do not own this bookmark\n");
            return;
        }

        std::string query = "DELETE FROM bookmarks WHERE id = " + std::to_string(bookmarkId);
        db.executeQuery(query);

        response.send(Http::Code::Ok, "Bookmark removed\n");
    }

private:
    Database& db;

    User* getUserByEmail(const std::string& email)
    {
        User* user = nullptr;

        std::string query = "SELECT * FROM users WHERE email = '" + email + "'";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db.getDB(), query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                user = new User;
                user->id = sqlite3_column_int(stmt, 0);
                user->email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                user->password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            }
            sqlite3_finalize(stmt);
        } else {
            std::cerr << "Error retrieving user: " << sqlite3_errmsg(db.getDB()) << std::endl;
        }

        return user;
    }

    std::vector<Bookmark> getBookmarksByUserId(int userId)
    {
        std::vector<Bookmark> bookmarks;

        std::string query = "SELECT * FROM bookmarks WHERE user_id = " + std::to_string(userId);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db.getDB(), query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                Bookmark bookmark;
                bookmark.id = sqlite3_column_int(stmt, 0);
                bookmark.link = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                bookmark.isPublic = sqlite3_column_int(stmt, 2);
                bookmark.userId = sqlite3_column_int(stmt, 3);
                bookmarks.push_back(bookmark);
            }
	    sqlite3_finalize(stmt);
        } else {
            std::cerr << "Error retrieving bookmarks: " << sqlite3_errmsg(db.getDB()) << std::endl;
        }

        return bookmarks;
    }

    std::vector<Bookmark> getPublicBookmarks()
    {
        std::vector<Bookmark> bookmarks;

        std::string query = "SELECT * FROM bookmarks WHERE is_public = 1";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db.getDB(), query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                Bookmark bookmark;
                bookmark.id = sqlite3_column_int(stmt, 0);
                bookmark.link = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                bookmark.isPublic = sqlite3_column_int(stmt, 2);
                bookmark.userId = sqlite3_column_int(stmt, 3);
                bookmarks.push_back(bookmark);
            }
            sqlite3_finalize(stmt);
        } else {
            std::cerr << "Error retrieving public bookmarks: " << sqlite3_errmsg(db.getDB()) << std::endl;
        }

        return bookmarks;
    }

    Bookmark* getBookmarkById(int bookmarkId)
    {
        Bookmark* bookmark = nullptr;

        std::string query = "SELECT * FROM bookmarks WHERE id = " + std::to_string(bookmarkId);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db.getDB(), query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                bookmark = new Bookmark;
                bookmark->id = sqlite3_column_int(stmt, 0);
                bookmark->link = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                bookmark->isPublic = sqlite3_column_int(stmt, 2);
                bookmark->userId = sqlite3_column_int(stmt, 3);
            }
            sqlite3_finalize(stmt);
        } else {
            std::cerr << "Error retrieving bookmark: " << sqlite3_errmsg(db.getDB()) << std::endl;
        }

        return bookmark;
    }

    int getUserIdFromToken(const Pistache::Rest::Request& request)
    {
        const std::string tokenPrefix = "Bearer ";	
        const auto authHeader = request.headers().tryGet<Pistache::Http::Header::Authorization>();

        // Check if the Authorization header exists and retrieve its value
        if (authHeader && authHeader->value().compare(0, tokenPrefix.size(), tokenPrefix) == 0) {
            std::string token = authHeader->value().substr(tokenPrefix.size());

            // Validate the token and retrieve the user ID
            std::string query = "SELECT * FROM bookmarks WHERE user_id = " + token;
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(db.getDB(), query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
                int userId = stoi(token);
                return userId;
            }
        }

	// Token is invalid or not present
	return -1;
    }

    void sendJsonResponse(Http::ResponseWriter& response, const std::vector<Bookmark>& bookmarks)
    {
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);

        writer.StartArray();
        for (const auto& bookmark : bookmarks) {
            writer.StartObject();
            writer.Key("id");
            writer.Int(bookmark.id);
            writer.Key("link");
            writer.String(bookmark.link.c_str());
            writer.Key("is_public");
            writer.Bool(bookmark.isPublic);
            writer.Key("user_id");
            writer.Int(bookmark.userId);
            writer.EndObject();
        }
        writer.EndArray();
        response.headers().add<Http::Header::ContentType>(MIME(Application, Json));
        response.send(Http::Code::Ok, buffer.GetString());
    }
};

int main()
{
    Database database("bookmark.db");
    if (!database.isValid()) {
        std::cerr << "Failed to open database" << std::endl;
        return 1;
    }

    // Set up Pistache HTTP server
    Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(8080));
    auto opts = Pistache::Http::Endpoint::options().threads(1);
    Http::Endpoint server(addr);
    server.init(opts);
    Rest::Router router;

    // Create bookmark handler
    BookmarkHandler bookmarkHandler(database);

    // User endpoints
    router.post("/users", Rest::Routes::bind(&BookmarkHandler::createUser, &bookmarkHandler));
    router.post("/login", Rest::Routes::bind(&BookmarkHandler::loginUser, &bookmarkHandler));

    // Bookmark endpoints
    router.get("/bookmarks/user", Rest::Routes::bind(&BookmarkHandler::getUserBookmarks, &bookmarkHandler));
    Rest::Routes::Get(router, "/bookmarks/public", [&](const Rest::Request& request, Http::ResponseWriter response) -> Rest::Route::Result {
        bookmarkHandler.getPublicBookmarks(request, std::move(response));
	return Pistache::Rest::Route::Result::Ok;
    });
    router.post("/bookmarks", Rest::Routes::bind(&BookmarkHandler::addBookmark, &bookmarkHandler));
    router.del("/bookmarks/:bookmarkId", Rest::Routes::bind(&BookmarkHandler::removeBookmark, &bookmarkHandler));

    // Start the server
    server.setHandler(router.handler());
    server.serve();

    return 0;
}
