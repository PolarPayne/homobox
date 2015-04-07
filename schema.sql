drop table if exists users;
create table users (
    user_id integer primary key autoincrement not null,
    name text not null unique,
    password text not null,
    admin integer
);

drop table if exists shouts;
create table shouts (
    shout_id integer primary key autoincrement,
    user_id integer not null,
    shout text not null,
    post_time integer not null
);
