CREATE TABLE USERS (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    surname VARCHAR(100),
    email VARCHAR(100),
    password VARCHAR(500),
    token VARCHAR(500),
    is_admin BOOLEAN
);

CREATE TABLE LOCKS(
    id SERIAL PRIMARY KEY,
    number VARCHAR(100),
    preview VARCHAR(100),
    about VARCHAR(100),
    token VARCHAR(500)
);

CREATE TABLE ACCESS(
    id SERIAL PRIMARY KEY,
    id_user INTEGER REFERENCES USERS(id),
    id_lock INTEGER REFERENCES LOCKS(id)
);