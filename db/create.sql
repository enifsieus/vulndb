CREATE DATABASE vulndb;

CREATE TABLE cve(
    id serial NOT NULL PRIMARY KEY,
    data jsonb NOT NULL
);

CREATE TABLE cpe(
    id serial NOT NULL PRIMARY KEY,
    data jsonb NOT NULL
);

CREATE TABLE osv(
    id serial NOT NULL PRIMARY KEY,
    ecosystem VARCHAR(64) NOT NULL DEFAULT '',
    data jsonb NOT NULL
);