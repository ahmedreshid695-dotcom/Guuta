CREATE DATABASE IF NOT EXISTS stu_register;
USE stu_register;

CREATE TABLE IF NOT EXISTS students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'student',
    picture VARCHAR(255) DEFAULT '',
    department VARCHAR(100) DEFAULT 'General',
    phone VARCHAR(50) DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    gender VARCHAR(30) DEFAULT '',
    university VARCHAR(255) DEFAULT '',
    registration_date DATE DEFAULT NULL,
    enrollment_status ENUM('Active', 'Inactive', 'Graduated') NOT NULL DEFAULT 'Active',
    registered_by_email VARCHAR(255) DEFAULT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    student_email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS student_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(64) NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    gender VARCHAR(30) DEFAULT '',
    date_of_birth DATE DEFAULT NULL,
    phone VARCHAR(50) DEFAULT '',
    email VARCHAR(255) DEFAULT NULL,
    university VARCHAR(255) DEFAULT '',
    faculty VARCHAR(255) DEFAULT '',
    department VARCHAR(255) DEFAULT '',
    year_of_study VARCHAR(50) DEFAULT '',
    semester VARCHAR(50) DEFAULT '',
    academic_year VARCHAR(50) DEFAULT '',
    student_photo VARCHAR(255) DEFAULT '',
    registration_date DATE NOT NULL,
    admin_email VARCHAR(255) NOT NULL,
    status ENUM('Active', 'Inactive', 'Graduated') NOT NULL DEFAULT 'Active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
