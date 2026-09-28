-- ============================================================
-- Zandsculpturen Pieterburen
-- Bijzondere mededelingen: rechten op de BESTAANDE tabel
-- public.site_settings, rij id = 'mededelingen'.
--
-- NIET automatisch uitgevoerd. Draai dit in de Supabase SQL Editor.
-- Er wordt GEEN nieuwe tabel aangemaakt.
--
-- Adminaccount (auth.users.id): 4ec8acac-7741-42a8-b639-7d8b8c6a7203
-- ============================================================


-- ---------- 0. inspectie (read-only, wijzigt niets) ----------

-- 0.1 hoe ziet site_settings eruit?
select column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public' and table_name = 'site_settings'
order by ordinal_position;

-- 0.2 staat RLS aan?
select relrowsecurity as rls_aan
from pg_class where oid = 'public.site_settings'::regclass;

-- 0.3 bestaande policies
select policyname, cmd, roles, permissive, qual, with_check
from pg_policies
where schemaname = 'public' and tablename = 'site_settings'
order by cmd, policyname;

-- 0.4 bestaande GRANTs
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'site_settings'
  and grantee in ('anon','authenticated')
order by grantee, privilege_type;

-- 0.5 huidige inhoud
select id, settings from public.site_settings order by id;


-- ============================================================
-- 1. openbaar lezen, alleen de rij 'mededelingen'
-- ============================================================
-- De rij 'openingstijden' uit het oude systeem blijft hiermee dicht.

alter table public.site_settings enable row level security;

grant select on public.site_settings to anon, authenticated;

drop policy if exists "mededelingen openbaar leesbaar" on public.site_settings;
create policy "mededelingen openbaar leesbaar"
  on public.site_settings
  for select
  to anon, authenticated
  using (id = 'mededelingen');


-- ============================================================
-- 2. schrijven, uitsluitend het adminaccount en alleen die rij
-- ============================================================
-- anon mag nooit schrijven.
revoke insert, update, delete, truncate on public.site_settings from anon;

-- De website doet een upsert: POST met
-- Prefer: resolution=merge-duplicates. Daarvoor zijn insert en update
-- beide nodig. DELETE wordt bewust NIET gegeven: een mededeling weghalen
-- gebeurt door het vinkje uit te zetten of het veld leeg te maken, dus de
-- rij hoeft nooit verwijderd te worden.
grant insert, update on public.site_settings to authenticated;

-- Twee policies in plaats van "for all", zodat DELETE ook op policyniveau
-- nergens is toegestaan. Beide zijn begrensd op id = 'mededelingen', zodat
-- de admin geen andere rij in site_settings kan overschrijven.
drop policy if exists "alleen admin mag mededelingen beheren"     on public.site_settings;
drop policy if exists "admin mag mededelingen toevoegen"          on public.site_settings;
drop policy if exists "admin mag mededelingen wijzigen"           on public.site_settings;

create policy "admin mag mededelingen toevoegen"
  on public.site_settings
  for insert
  to authenticated
  with check (id = 'mededelingen' and auth.uid() = '4ec8acac-7741-42a8-b639-7d8b8c6a7203'::uuid);

create policy "admin mag mededelingen wijzigen"
  on public.site_settings
  for update
  to authenticated
  using      (id = 'mededelingen' and auth.uid() = '4ec8acac-7741-42a8-b639-7d8b8c6a7203'::uuid)
  with check (id = 'mededelingen' and auth.uid() = '4ec8acac-7741-42a8-b639-7d8b8c6a7203'::uuid);


-- ============================================================
-- 3. controleren (read-only)
-- ============================================================

-- a) precies twee policies verwacht, beide begrensd op id = 'mededelingen'
select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public' and tablename = 'site_settings'
order by cmd, policyname;

-- b) rechten: anon alleen SELECT, authenticated SELECT + INSERT + UPDATE
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'site_settings'
  and grantee in ('anon','authenticated')
order by grantee, privilege_type;

-- c) de oude rij 'openingstijden' mag NIET openbaar leesbaar zijn.
--    Test dit met de publishable key:
--      GET /rest/v1/site_settings?select=settings&id=eq.openingstijden  -> lege array
--      GET /rest/v1/site_settings?select=settings&id=eq.mededelingen    -> HTTP 200


-- ============================================================
-- Terugdraaien
-- ============================================================
-- drop policy if exists "alleen admin mag mededelingen beheren" on public.site_settings;
-- drop policy if exists "mededelingen openbaar leesbaar"        on public.site_settings;
-- revoke insert, update on public.site_settings from authenticated;
-- revoke select on public.site_settings from anon, authenticated;
