-- Create the database
CREATE DATABASE IF NOT EXISTS ewo_db;

-- Create user and grant privileges
CREATE USER IF NOT EXISTS 'ewo_user'@'%' IDENTIFIED BY 'ewo_password';
GRANT ALL PRIVILEGES ON ewo_db.* TO 'ewo_user'@'%';
FLUSH PRIVILEGES;
