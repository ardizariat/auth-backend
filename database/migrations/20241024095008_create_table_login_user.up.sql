CREATE TABLE login_user (
	id varchar(255) NOT NULL,
	user_id varchar(255) NOT NULL,
	user_agent varchar(255) NULL,
	ip_address varchar(100) NULL,
	firebase_token TEXT NULL,
	model varchar(255) NULL,
	refresh_token TEXT NULL,
	created_at timestamptz DEFAULT now() NOT NULL,
	updated_at timestamptz DEFAULT now() NOT NULL,
	CONSTRAINT login_user_pkey PRIMARY KEY (id),
	CONSTRAINT login_user_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE NO ACTION ON UPDATE CASCADE
);