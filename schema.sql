drop table if exists entries;
create table entries (
  id integer primary key autoincrement,
  title text not null,
  text text not null
);

drop table if exists users;
create table users (
  id integer primary key autoincrement,
  usrname char(10) not null,
  passwd char(10) not null
);