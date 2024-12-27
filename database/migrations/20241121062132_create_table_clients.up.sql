CREATE TABLE clients (
	id varchar(255) NOT NULL,
	name varchar(255) NOT NULL,
	enabled bool DEFAULT false NOT NULL,
	base_url varchar(255) NOT NULL,
	callback_url text NOT NULL,
	description varchar(255) NULL,
	created_at timestamptz DEFAULT now() NOT NULL,
	updated_at timestamptz DEFAULT now() NOT NULL,
	deleted_at timestamptz NULL,
	CONSTRAINT clients_pkey PRIMARY KEY (id),
    CONSTRAINT clients_name_key UNIQUE (name),
    CONSTRAINT clients_base_url_key UNIQUE (base_url)
);