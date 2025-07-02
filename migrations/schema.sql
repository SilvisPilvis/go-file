-- Create all tables

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(30) NOT NULL,
    password VARCHAR(97) NOT NULL
);

CREATE TABLE stores (
    id SERIAL PRIMARY KEY,
    name VARCHAR(30) NOT NULL,
    cover INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    original_name VARCHAR(256) NOT NULL,
    content_type VARCHAR(255) NOT NULL,
    md5 VARCHAR(32) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE TABLE user_store (
    id SERIAL PRIMARY KEY,
    userId INTEGER NOT NULL,
    storeId INTEGER NOT NULL,
    FOREIGN KEY(userId)
    REFERENCES users(id),
    FOREIGN KEY(storeId)
    REFERENCES stores(id)
);

CREATE TABLE file_store (
    id SERIAL PRIMARY KEY,
    fileId INTEGER NOT NULL,
    storeId INTEGER NOT NULL,
    FOREIGN KEY(fileId)
    REFERENCES files(id),
    FOREIGN KEY(storeId)
    REFERENCES stores(id)
);
