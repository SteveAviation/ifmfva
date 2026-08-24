-- ============================================================
--  MFVA Supabase Schema
--  Run this in Supabase SQL Editor (Dashboard → SQL → New Query)
-- ============================================================

-- 1. Create the members table
create table if not exists members (
  email       text primary key,
  data        jsonb not null,
  updated_at  timestamptz default now()
);

-- 2. Enable Row Level Security
alter table members enable row level security;

-- 3. Allow anyone with the anon key to read members
--    (needed so every device can see applications)
drop policy if exists "Members are readable by all" on members;
create policy "Members are readable by all"
  on members for select
  using (true);

-- 4. Allow anyone with the anon key to insert/update members
--    (needed so users can submit applications from any device)
drop policy if exists "Members are writable by all" on members;
create policy "Members are writable by all"
  on members for all
  using (true)
  with check (true);

-- 5. Allow deletes (admin removes a member)
drop policy if exists "Members are deletable by all" on members;
create policy "Members are deletable by all"
  on members for delete
  using (true);

-- Done! You can verify by running:
--   select email, data->>'displayName' as name, data->>'status' as status
--   from members order by updated_at desc;
