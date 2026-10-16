-- =====================================================================
-- Link Hub database setup (Supabase)
-- 1) CHANGE the email on the line marked  <<< YOUR EMAIL  (section 2)
-- 2) Paste the whole file into Supabase -> SQL Editor -> Run
-- It is safe to run this file more than once.
-- =====================================================================

-- ---------- 1. Tables ----------
create table if not exists public.clients (
  id         uuid primary key default gen_random_uuid(),
  slug       text unique not null check (slug ~ '^[a-z0-9_-]{2,40}$'),
  name       text not null default '' check (length(name) <= 100),
  handle     text not null default '' check (length(handle) <= 100),
  bio        text not null default '' check (length(bio) <= 400),
  avatar     text not null default '' check (length(avatar) <= 500),
  footer     text not null default '' check (length(footer) <= 200),
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.client_secrets (
  client_id   uuid primary key references public.clients(id) on delete cascade,
  submit_code text not null
);

create table if not exists public.links (
  id        uuid primary key default gen_random_uuid(),
  client_id uuid not null references public.clients(id) on delete cascade,
  title     text not null default '' check (length(title) <= 120),
  url       text not null check (length(url) <= 600 and url ~* '^(https?://|mailto:|tel:)'),
  position  int  not null default 0
);

create table if not exists public.videos (
  id        uuid primary key default gen_random_uuid(),
  client_id uuid not null references public.clients(id) on delete cascade,
  url       text not null check (length(url) <= 600 and url ~* '^https?://'),
  platform  text not null default 'instagram' check (platform in ('instagram','youtube','tiktok')),
  caption   text not null default '' check (length(caption) <= 300),
  position  int  not null default 0
);

create table if not exists public.submissions (
  id         uuid primary key default gen_random_uuid(),
  client_id  uuid not null references public.clients(id) on delete cascade,
  url        text not null check (length(url) <= 600),
  note       text not null default '' check (length(note) <= 300),
  status     text not null default 'pending',
  created_at timestamptz not null default now()
);

create index if not exists links_client_idx       on public.links(client_id);
create index if not exists videos_client_idx      on public.videos(client_id);
create index if not exists submissions_client_idx on public.submissions(client_id);

-- ---------- 2. Who is the admin? (only you) ----------
create table if not exists public.admin_emails (email text primary key);
insert into public.admin_emails(email) values ('you@example.com')   -- <<< YOUR EMAIL (the one you log in with)
on conflict do nothing;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.admin_emails e
    where lower(e.email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  );
$$;

-- ---------- 3. Auto-create a private "submit code" for every new client ----------
create or replace function public.make_secret() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.client_secrets(client_id, submit_code)
  values (new.id, substr(md5(random()::text || clock_timestamp()::text || new.id::text), 1, 12));
  return new;
end $$;

drop trigger if exists clients_secret on public.clients;
create trigger clients_secret after insert on public.clients
for each row execute function public.make_secret();

-- ---------- 4. Clients send links through this function only ----------
create or replace function public.submit_link(p_slug text, p_code text, p_url text, p_note text default '')
returns void language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  select c.id into cid
  from public.clients c
  join public.client_secrets s on s.client_id = c.id
  where c.slug = lower(p_slug) and s.submit_code = p_code and c.active;
  if cid is null then raise exception 'invalid code'; end if;
  if p_url is null or length(p_url) > 600 or p_url !~* '^https?://' then raise exception 'bad link'; end if;
  if (select count(*) from public.submissions where client_id = cid and status = 'pending') >= 60 then
    raise exception 'too many pending links';
  end if;
  insert into public.submissions(client_id, url, note) values (cid, p_url, left(coalesce(p_note, ''), 300));
end $$;

-- ---------- 5. Security (Row Level Security) ----------
alter table public.clients        enable row level security;
alter table public.client_secrets enable row level security;
alter table public.links          enable row level security;
alter table public.videos         enable row level security;
alter table public.submissions    enable row level security;
alter table public.admin_emails   enable row level security;

-- visitors can only READ live client pages
drop policy if exists "clients public read" on public.clients;
create policy "clients public read" on public.clients for select to anon, authenticated
  using (active or public.is_admin());

drop policy if exists "links public read" on public.links;
create policy "links public read" on public.links for select to anon, authenticated
  using (exists (select 1 from public.clients c where c.id = client_id and c.active) or public.is_admin());

drop policy if exists "videos public read" on public.videos;
create policy "videos public read" on public.videos for select to anon, authenticated
  using (exists (select 1 from public.clients c where c.id = client_id and c.active) or public.is_admin());

-- only the admin can change anything
drop policy if exists "clients admin all" on public.clients;
create policy "clients admin all" on public.clients for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "links admin all" on public.links;
create policy "links admin all" on public.links for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "videos admin all" on public.videos;
create policy "videos admin all" on public.videos for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "submissions admin all" on public.submissions;
create policy "submissions admin all" on public.submissions for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "secrets admin all" on public.client_secrets;
create policy "secrets admin all" on public.client_secrets for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ---------- 6. Permissions ----------
grant usage on schema public to anon, authenticated;
grant select on public.clients, public.links, public.videos to anon;
grant select, insert, update, delete on
  public.clients, public.links, public.videos, public.submissions, public.client_secrets to authenticated;
revoke all on public.admin_emails from anon, authenticated;
grant execute on function public.submit_link(text, text, text, text) to anon, authenticated;
grant execute on function public.is_admin() to anon, authenticated;
