CREATE DATABASE hpkp;

USE hpkp;

CREATE TABLE reports
(
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,

	created_at DATETIME NOT NULL,
	request_ip VARCHAR(45) NOT NULL,
	user_agent VARCHAR(255) NOT NULL,

	date_time DATETIME NOT NULL,
	effective_expiration_date DATETIME NOT NULL,
	hostname VARCHAR(255) NOT NULL, -- ?
	noted_hostname VARCHAR(255) NOT NULL, -- ?
	port SMALLINT UNSIGNED NOT NULL,
	include_subdomains TINYINT(1) NOT NULL,

	PRIMARY KEY (id)
);

CREATE TABLE pins
(
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	pin CHAR(44) NOT NULL, -- 'pin-sha256="(.{44})"

	PRIMARY KEY (id),
	UNIQUE KEY (pin)
);

CREATE TABLE report_pins
(
	report_id INT UNSIGNED NOT NULL,
	pin_id INT UNSIGNED NOT NULL,

	-- doesn't make sense to have duplicate pins,
	--	even though the rfc allows it.
	PRIMARY KEY (report_id, pin_id),

	FOREIGN KEY (report_id)
		REFERENCES report(id)
		ON UPDATE CASCADE
		ON DELETE CASCADE,
	FOREIGN KEY (pin_id)
		REFERENCES pins(id)
		ON UPDATE RESTRICT
		ON DELETE RESTRICT
);

CREATE TABLE certs
(
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	cert TEXT NOT NULL,
	pin CHAR(44) NOT NULL,

	PRIMARY KEY (id),
	UNIQUE KEY (pin)
);

CREATE TABLE report_s_chain
(
	report_id INT UNSIGNED NOT NULL,
	cert_id INT UNSIGNED NOT NULL,

	-- I have yet to see a chain with >255 certs
	position TINYINT UNSIGNED NOT NULL,

	PRIMARY KEY (report_id, cert_id),

	FOREIGN KEY (report_id)
		REFERENCES report(id)
		ON UPDATE CASCADE
		ON DELETE CASCADE,
	FOREIGN KEY (cert_id)
		REFERENCES certs(id)
		ON UPDATE RESTRICT
		ON DELETE RESTRICT
);

CREATE TABLE report_v_chain
(
	report_id INT UNSIGNED NOT NULL,
	cert_id INT UNSIGNED NOT NULL,

	position TINYINT UNSIGNED NOT NULL,

	PRIMARY KEY (report_id, cert_id)

	FOREIGN KEY (report_id)
		REFERENCES report(id)
		ON UPDATE CASCADE
		ON DELETE CASCADE,
	FOREIGN KEY (cert_id)
		REFERENCES certs(id)
		ON UPDATE RESTRICT
		ON DELETE RESTRICT
);
