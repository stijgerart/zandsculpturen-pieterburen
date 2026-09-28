-- ============================================================
-- Zandsculpturen Pieterburen
-- RLS-opzet voor public.opening_hours
--
-- NIET automatisch uitgevoerd. Draai dit in de Supabase SQL Editor.
-- Er worden GEEN nieuwe tabellen aangemaakt.
--
-- Adminaccount (auth.users.id): 4ec8acac-7741-42a8-b639-7d8b8c6a7203
--
-- Uitgangssituatie, gemeten met 4.0 op 2026-09-28:
--   Admin mag openingstijden toevoegen    INSERT  {authenticated}  qual NULL
--   Admin mag openingstijden verwijderen  DELETE  {authenticated}  qual true
--   Admin mag openingstijden wijzigen     UPDATE  {authenticated}  qual true
--   Iedereen mag openingstijden bekijken  SELECT  {anon,authenticated}  qual true
--   openingstijden openbaar leesbaar      SELECT  {anon,authenticated}  qual true
--
-- De eerste drie stonden open voor ELKE ingelogde gebruiker.
-- De laatste twee zijn identiek: een dubbele leespolicy.
-- ============================================================


-- ============================================================
-- STAP 0: inspectie (read-only, wijzigt niets)
-- ============================================================

-- 0.1 staat RLS aan?
select relrowsecurity as rls_aan, relforcerowsecurity as rls_ook_voor_eigenaar
from pg_class where oid = 'public.opening_hours'::regclass;

-- 0.2 bestaande policies
select policyname, cmd, roles, permissive, qual, with_check
from pg_policies where schemaname = 'public' and tablename = 'opening_hours'
order by cmd, policyname;

-- 0.3 bestaande GRANTs
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'opening_hours'
order by grantee, privilege_type;

-- 0.4 is id identity of bigserial?
select column_name, is_identity, identity_generation, column_default
from information_schema.columns
where table_schema = 'public' and table_name = 'opening_hours' and column_name = 'id';

-- 0.5 volledige kolomdefinitie
select column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public' and table_name = 'opening_hours'
order by ordinal_position;

-- 0.6 huidige inhoud
select id, date_from, date_to, time_from, time_to, closed
from public.opening_hours order by date_from, time_from;


-- ============================================================
-- STAP 1: openbaar lezen  --  UITGEVOERD op 2026-09-27
-- ============================================================
-- De leespolicy bestond al ("Iedereen mag openingstijden bekijken").
-- Wat ontbrak was de GRANT; die veroorzaakte de 42501.
-- De policy die stap 1 toevoegde is daarmee een duplicaat.
--
-- alter table public.opening_hours enable row level security;
-- grant select on public.opening_hours to anon, authenticated;
-- create policy "openingstijden openbaar leesbaar" ...  <- duplicaat, zie 4.6


-- ============================================================
-- STAP 4: schrijven, uitsluitend voor het adminaccount
--
-- Draai 4.1 t/m 4.5 in EEN keer. Tussen 4.1 en 4.5 kan niemand
-- schrijven; dat is een paar milliseconden, geen bezwaar.
-- ============================================================


-- ---------- 4.1 de drie open schrijfpolicies weghalen ----------
-- Namen exact zoals in pg_policies, inclusief hoofdletter en spaties.
-- Policynamen zijn case-sensitive.

drop policy if exists "Admin mag openingstijden toevoegen"    on public.opening_hours;
drop policy if exists "Admin mag openingstijden wijzigen"      on public.opening_hours;
drop policy if exists "Admin mag openingstijden verwijderen"   on public.opening_hours;

-- ook de nieuwe naam, zodat 4.5 herhaalbaar is
drop policy if exists "alleen admin mag openingstijden beheren" on public.opening_hours;


-- ---------- 4.2 sweep: vang alles wat 4.1 heeft gemist ----------
-- Verwijdert elke overgebleven policy die niet uitsluitend SELECT is.
-- Beide leespolicies blijven staan (cmd = SELECT).
-- Verwacht: "niets meer te verwijderen".

do $$
declare
  p record;
  aantal int := 0;
begin
  for p in
    select policyname
    from pg_policies
    where schemaname = 'public'
      and tablename  = 'opening_hours'
      and cmd <> 'SELECT'
  loop
    raise notice 'sweep verwijderde nog: %', p.policyname;
    execute format('drop policy %I on public.opening_hours', p.policyname);
    aantal := aantal + 1;
  end loop;

  if aantal = 0 then
    raise notice 'sweep: niets meer te verwijderen, 4.1 was volledig';
  end if;
end $$;


-- ---------- 4.3 anon mag nooit schrijven ----------
-- anon is iedereen met de publishable key, en die staat leesbaar
-- in index.html. Onschadelijk als anon deze rechten al niet had.

revoke insert, update, delete, truncate on public.opening_hours from anon;


-- ---------- 4.4 schrijfrecht voor ingelogde gebruikers ----------
-- Alleen de GRANT-laag. Wie er doorheen mag bepaalt 4.5.
-- Zonder 4.5 komt er niets door, want RLS staat aan.

grant insert, update, delete on public.opening_hours to authenticated;


-- ---------- 4.5 schrijfpolicy, uitsluitend deze ene UID ----------
-- using      -> SELECT, UPDATE, DELETE : welke bestaande rijen mag je raken
-- with check -> INSERT, UPDATE         : welke waarde mag erin
--
-- Beide nodig. De oude INSERT-policy had qual NULL: bij INSERT wordt
-- qual nooit gebruikt, alleen with_check. Precies daarom staat hier
-- expliciet ook with check.

create policy "alleen admin mag openingstijden beheren"
  on public.opening_hours
  for all
  to authenticated
  using      (auth.uid() = '4ec8acac-7741-42a8-b639-7d8b8c6a7203'::uuid)
  with check (auth.uid() = '4ec8acac-7741-42a8-b639-7d8b8c6a7203'::uuid);


-- ---------- 4.6 OPTIONEEL: dubbele leespolicy opruimen ----------
-- "Iedereen mag openingstijden bekijken" en "openingstijden openbaar
-- leesbaar" zijn identiek: SELECT, {anon,authenticated}, using true.
-- Twee identieke permissive policies doen samen niets anders dan een.
-- Functioneel dus geen probleem, alleen verwarrend.
-- Houd de oorspronkelijke, verwijder het duplicaat van stap 1:
--
-- drop policy if exists "openingstijden openbaar leesbaar" on public.opening_hours;


-- ---------- 4.7 alleen als 0.4 toont: is_identity = NO met nextval(...) ----------
-- grant usage, select on sequence public.opening_hours_id_seq to authenticated;


-- ---------- 4.8 controleren (read-only) ----------

-- a) bestaat het adminaccount en is het bevestigd? Verwacht 1 rij.
select id, email, email_confirmed_at, last_sign_in_at
from auth.users
where id = '4ec8acac-7741-42a8-b639-7d8b8c6a7203'::uuid;

-- b) eindstand policies.
--    Verwacht 3 rijen (of 2 als je 4.6 hebt gedraaid):
--      alleen admin mag openingstijden beheren | ALL    | {authenticated}
--      Iedereen mag openingstijden bekijken    | SELECT | {anon,authenticated}
--      openingstijden openbaar leesbaar        | SELECT | {anon,authenticated}
select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public' and tablename = 'opening_hours'
order by cmd, policyname;

-- c) geen schrijfpolicy buiten de nieuwe. Verwacht exact 1 rij,
--    met de UID in zowel qual als with_check.
select policyname, cmd, qual, with_check
from pg_policies
where schemaname = 'public' and tablename = 'opening_hours' and cmd <> 'SELECT';

-- d) eindstand rechten.
--    Verwacht: anon alleen SELECT.
--              authenticated SELECT + INSERT + UPDATE + DELETE.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'opening_hours'
  and grantee in ('anon','authenticated')
order by grantee, privilege_type;

-- e) staan er onbekende accounts? Registratie stond open.
select id, email, created_at, last_sign_in_at
from auth.users order by created_at;


-- ============================================================
-- STAP 5: publieke registratie uitzetten  --  NA controle van 4.8
-- ============================================================
-- Geen SQL. Dashboard -> Authentication -> Sign In / Providers ->
-- "Allow new users to sign up" uit.


-- ============================================================
-- Tweede admin later toevoegen
-- ============================================================
-- alter policy "alleen admin mag openingstijden beheren"
--   on public.opening_hours
--   using      (auth.uid() in ('4ec8acac-7741-42a8-b639-7d8b8c6a7203'::uuid, '<UUID_2>'::uuid))
--   with check (auth.uid() in ('4ec8acac-7741-42a8-b639-7d8b8c6a7203'::uuid, '<UUID_2>'::uuid));


-- ============================================================
-- Terugdraaien
-- ============================================================
-- Naar de strakke policy terug (na een mislukte wijziging):
-- drop policy if exists "alleen admin mag openingstijden beheren" on public.opening_hours;
-- revoke insert, update, delete on public.opening_hours from authenticated;
--
-- De oude, open situatie terugzetten -- NIET aan te raden, elke
-- ingelogde gebruiker kon hiermee schrijven:
-- create policy "Admin mag openingstijden toevoegen"   on public.opening_hours for insert to authenticated with check (true);
-- create policy "Admin mag openingstijden wijzigen"    on public.opening_hours for update to authenticated using (true) with check (true);
-- create policy "Admin mag openingstijden verwijderen" on public.opening_hours for delete to authenticated using (true);
