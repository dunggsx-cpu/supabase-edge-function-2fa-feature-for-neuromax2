drop table if exists user_security cascade;

create table user_security (
  user_id uuid primary key references auth.users(id) on delete cascade,
  webauthn_credentials jsonb default '[]'::jsonb,
  webauthn_enabled boolean default false,
  totp_secret text,
  totp_enabled boolean default false,
  enable_login boolean default false,
  current_challenge text,
  created_at timestamptz default now()
);
