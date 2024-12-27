CREATE TABLE login_user (
	id varchar(255) NOT NULL,
	user_id varchar(255) NOT NULL,
	user_agent varchar(255) NULL,
	ip_address varchar(100) NULL,
	firebase_token TEXT NULL,
	key TEXT NOT NULL,
	model varchar(255) NULL,
	refresh_token TEXT NULL,
	is_validated BOOLEAN DEFAULT FALSE,
	created_at timestamptz DEFAULT now() NOT NULL,
	updated_at timestamptz DEFAULT now() NOT NULL,
	CONSTRAINT login_user_pkey PRIMARY KEY (id)
);