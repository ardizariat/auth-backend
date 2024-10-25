CREATE TABLE users (
	id varchar(255) NOT NULL,
	credential_id varchar(255) NOT NULL,
	name varchar(255) NOT NULL,
	username varchar(255) NOT NULL,
	email varchar(255) NOT NULL,
	is_active bool DEFAULT true NULL,
	password text NOT NULL,
	verified_at timestamptz NULL,
	last_login timestamptz NULL,
	pin int4 DEFAULT 1111 NULL,
	created_at timestamptz DEFAULT now() NOT NULL,
	updated_at timestamptz DEFAULT now() NOT NULL,
	deleted_at timestamptz NULL,
	CONSTRAINT users_pkey PRIMARY KEY (id),
	CONSTRAINT users_username_key UNIQUE (username),
	CONSTRAINT users_credential_id_key UNIQUE (credential_id)
);