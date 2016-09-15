CREATE DATABASE hpkp;

USE hpkp;

CREATE TABLE reports
(
	id int unsigned not null auto_increment,
	created_at datetime not null,
	request_ip varchar(255) not null,
	user_agent varchar(255) not null,
	date_time datetime not null,
	effective_expiration_date datetime not null,
	hostname varchar(255) not null,
	noted_hostname varchar(255) not null,
	port smallint unsigned not null,
	include_subdomains tinyint unsigned not null,

	PRIMARY KEY (id)
);

CREATE TABLE pins
(
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	pin CHAR(44) NOT NULL, -- 'pin-sha256="(.{44})"

	PRIMARY KEY (id)
);

CREATE TABLE report_pins
(
	report_id int unsigned not null,
	pin_id int unsigned not null,

	primary key (report_id, pin_id)
);

CREATE TABLE certs
(
	id int unsigned not null auto_increment,
	cert text not null,
	pin char(44) not null,
	primary key (id),
	unique key (pin)
);

CREATE TABLE report_s_chain
(
	report_id int unsigned not null,
	cert_id int unsigned not null,
	position tinyint unsigned not null,

	primary key (report_id, cert_id)
);

CREATE TABLE report_v_chain
(
	report_id int unsigned not null,
	cert_id int unsigned not null,
	position tinyint unsigned not null,

	primary key (report_id, cert_id)
);
