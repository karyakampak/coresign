CREATE TABLE IF NOT EXISTS example (
    id SERIAL PRIMARY KEY,
    data VARCHAR(100) NOT NULL
);

INSERT INTO example (data) VALUES ('Initial data');
