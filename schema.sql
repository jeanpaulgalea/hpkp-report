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
		REFERENCES reports(id)
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
		REFERENCES reports(id)
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

	PRIMARY KEY (report_id, cert_id),

	FOREIGN KEY (report_id)
		REFERENCES reports(id)
		ON UPDATE CASCADE
		ON DELETE CASCADE,
	FOREIGN KEY (cert_id)
		REFERENCES certs(id)
		ON UPDATE RESTRICT
		ON DELETE RESTRICT
);

CREATE VIEW violations AS
SELECT

reports.id,

reports.created_at,
reports.request_ip,
reports.user_agent,

reports.date_time,
reports.effective_expiration_date,
reports.hostname,
reports.noted_hostname,
reports.port,
reports.include_subdomains,

(SELECT GROUP_CONCAT(pins.pin SEPARATOR '\n')
 FROM report_pins
 INNER JOIN pins
	ON report_pins.pin_id = pins.id
 WHERE report_pins.report_id = reports.id
 GROUP BY report_pins.report_id) AS known_pins,

(SELECT GROUP_CONCAT(certs.cert SEPARATOR '\n')
 FROM report_s_chain
 INNER JOIN certs
	ON report_s_chain.cert_id = certs.id
 WHERE report_s_chain.report_id = reports.id
 GROUP BY report_s_chain.report_id
 ORDER BY report_s_chain.position) AS served_certificate_chain,

(SELECT GROUP_CONCAT(certs.cert SEPARATOR '\n')
 FROM report_v_chain
 INNER JOIN certs
	ON report_v_chain.cert_id = certs.id
 WHERE report_v_chain.report_id = reports.id
 GROUP BY report_v_chain.report_id
 ORDER BY report_v_chain.position) AS validated_certificate_chain

FROM reports
