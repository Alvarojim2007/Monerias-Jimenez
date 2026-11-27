-- =====================================================================
-- database_setup.sql
-- Sistema de Gestión de Equipos del CICT (Monerías Jiménez S.L.)
-- Supabase (PostgreSQL). Ejecutar COMPLETO en: SQL Editor > New query > Run
-- Es re-ejecutable: usa IF NOT EXISTS / DROP ... IF EXISTS / CREATE OR REPLACE.
-- RNF cubiertos: RNF-08 (RLS), RNF-14 (auditoría inmutable) + Realtime.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. TABLAS
-- ---------------------------------------------------------------------

create table if not exists public.perfiles (
  id                  uuid primary key references auth.users(id) on delete cascade,
  nombre              text not null,
  email               text not null unique,
  nif                 text not null unique,
  vinculacion         text check (vinculacion in ('UCO','EXTERNO')),
  organizacion        text not null,
  rol                 text not null default 'investigador'
                      check (rol in ('investigador','tecnico','administrador','responsable_economico')),
  estado_cuenta       text not null default 'pendiente'
                      check (estado_cuenta in ('pendiente','aprobada','rechazada')),
  consentimiento_rgpd boolean not null,
  created_at          timestamptz not null default now()
);

create table if not exists public.equipos (
  id               uuid primary key default gen_random_uuid(),
  codigo           text not null unique,
  nombre           text not null,
  laboratorio      text not null,
  especificaciones text,
  ubicacion_fisica text not null,
  estado           text not null default 'disponible'
                   check (estado in ('disponible','ocupado','bloqueado_mantenimiento')),
  acceso_publico   boolean not null default true,
  hora_apertura    time not null default '08:00',
  hora_cierre      time not null default '20:00',
  created_at       timestamptz not null default now()
);

create table if not exists public.reservas (
  id            uuid primary key default gen_random_uuid(),
  usuario_id    uuid not null references public.perfiles(id),
  equipo_id     uuid not null references public.equipos(id),
  fecha_inicio  timestamptz not null,
  fecha_fin     timestamptz not null,
  estado        text not null default 'confirmada'
                check (estado in ('confirmada','pendiente_prioridad','cancelada','desplazada_uco')),
  prioridad_uco boolean not null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint reservas_fechas_validas check (fecha_fin > fecha_inicio)
);
create index if not exists idx_reservas_equipo_fechas on public.reservas (equipo_id, fecha_inicio, fecha_fin);
create index if not exists idx_reservas_usuario on public.reservas (usuario_id);

create table if not exists public.incidencias (
  id                uuid primary key default gen_random_uuid(),
  equipo_id         uuid not null references public.equipos(id),
  reportador_id     uuid not null references public.perfiles(id),
  tecnico_id        uuid references public.perfiles(id),
  descripcion       text not null,
  estado            text not null default 'abierta'
                    check (estado in ('abierta','en_proceso','cerrada')),
  es_grave          boolean not null default false,
  solucion_aplicada text,
  created_at        timestamptz not null default now(),
  closed_at         timestamptz
);
create index if not exists idx_incidencias_equipo on public.incidencias (equipo_id);

create table if not exists public.notificaciones (
  id         uuid primary key default gen_random_uuid(),
  usuario_id uuid not null references public.perfiles(id) on delete cascade,
  tipo       text,
  titulo     text,
  mensaje    text,
  leida      boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists idx_notif_usuario on public.notificaciones (usuario_id, leida);

-- RNF-14: sin FK a propósito, para que el registro sobreviva al borrado de usuarios.
create table if not exists public.auditoria (
  id             uuid primary key default gen_random_uuid(),
  usuario_id     uuid,
  accion         text not null,
  tabla_afectada text not null,
  registro_id    uuid,
  detalles       jsonb,
  created_at     timestamptz not null default now()
);
create index if not exists idx_auditoria_tabla on public.auditoria (tabla_afectada, created_at desc);

-- ---------------------------------------------------------------------
-- 2. FUNCIONES AUXILIARES (SECURITY DEFINER evita recursión en RLS)
-- ---------------------------------------------------------------------

create or replace function public.rol_actual()
returns text language sql stable security definer set search_path = public as $$
  select rol from public.perfiles where id = auth.uid()
$$;

create or replace function public.cuenta_aprobada()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select estado_cuenta = 'aprobada' from public.perfiles where id = auth.uid()), false)
$$;

-- ---------------------------------------------------------------------
-- 3. TRIGGER: PERFIL AUTOMÁTICO AL REGISTRARSE EN auth.users
--    El rol y el estado NUNCA se leen de los metadatos (evita escalada de privilegios).
-- ---------------------------------------------------------------------

create or replace function public.fn_crear_perfil()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  m jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
begin
  insert into public.perfiles (id, nombre, email, nif, vinculacion, organizacion, consentimiento_rgpd)
  values (
    new.id,
    coalesce(nullif(m->>'nombre',''), split_part(new.email,'@',1)),
    new.email,
    coalesce(nullif(m->>'nif',''), 'SIN-NIF-' || new.id::text),
    case when m->>'vinculacion' in ('UCO','EXTERNO') then m->>'vinculacion' else 'EXTERNO' end,
    coalesce(nullif(m->>'organizacion',''), 'No indicada'),
    coalesce((m->>'consentimiento_rgpd')::boolean, false)
  );
  return new;
end $$;

drop trigger if exists trg_crear_perfil on auth.users;
create trigger trg_crear_perfil
  after insert on auth.users
  for each row execute function public.fn_crear_perfil();

-- ---------------------------------------------------------------------
-- 4. TRIGGERS DE NEGOCIO
-- ---------------------------------------------------------------------

-- 4.1 Un usuario normal no puede cambiarse rol/estado/email/nif (solo administrador).
--     Desde el SQL Editor (auth.uid() null) sí se permite: así se crea el primer admin.
create or replace function public.fn_proteger_perfil()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and coalesce(public.rol_actual(),'') <> 'administrador' then
    if new.id            is distinct from old.id
    or new.rol           is distinct from old.rol
    or new.estado_cuenta is distinct from old.estado_cuenta
    or new.email         is distinct from old.email
    or new.nif           is distinct from old.nif then
      raise exception 'Solo un administrador puede modificar rol, estado, email o NIF.' using errcode = '42501';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists trg_proteger_perfil on public.perfiles;
create trigger trg_proteger_perfil
  before update on public.perfiles
  for each row execute function public.fn_proteger_perfil();

-- 4.2 Reservas: updated_at automático y prioridad_uco calculada en servidor (no manipulable).
create or replace function public.fn_reservas_before()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.prioridad_uco := coalesce((select vinculacion = 'UCO' from public.perfiles where id = new.usuario_id), false);
  else
    new.prioridad_uco := old.prioridad_uco;
  end if;
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists trg_reservas_before on public.reservas;
create trigger trg_reservas_before
  before insert or update on public.reservas
  for each row execute function public.fn_reservas_before();

-- 4.3 Notificación automática: reserva desplazada por prioridad UCO.
create or replace function public.fn_notif_reserva_desplazada()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.estado = 'desplazada_uco' and old.estado is distinct from new.estado then
    insert into public.notificaciones (usuario_id, tipo, titulo, mensaje)
    values (new.usuario_id, 'reserva', 'Reserva desplazada',
            'Tu reserva ha sido desplazada por una reserva con prioridad UCO.');
  end if;
  return new;
end $$;

drop trigger if exists trg_notif_reserva_desplazada on public.reservas;
create trigger trg_notif_reserva_desplazada
  after update on public.reservas
  for each row execute function public.fn_notif_reserva_desplazada();

-- 4.4 Notificación automática: incidencia grave -> técnicos y administradores.
create or replace function public.fn_notif_incidencia_grave()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.es_grave then
    insert into public.notificaciones (usuario_id, tipo, titulo, mensaje)
    select p.id, 'incidencia', 'Incidencia grave',
           'Se ha reportado una incidencia grave: ' || left(new.descripcion, 140)
    from public.perfiles p
    where p.rol in ('tecnico','administrador') and p.estado_cuenta = 'aprobada';
  end if;
  return new;
end $$;

drop trigger if exists trg_notif_incidencia_grave on public.incidencias;
create trigger trg_notif_incidencia_grave
  after insert on public.incidencias
  for each row execute function public.fn_notif_incidencia_grave();

-- ---------------------------------------------------------------------
-- 5. AUDITORÍA (RNF-14)
-- ---------------------------------------------------------------------

create or replace function public.fn_auditar()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_reg uuid;
  v_det jsonb;
begin
  if tg_op = 'DELETE' then
    v_reg := (to_jsonb(old)->>'id')::uuid;
    v_det := jsonb_build_object('antes', to_jsonb(old));
  elsif tg_op = 'UPDATE' then
    v_reg := (to_jsonb(new)->>'id')::uuid;
    v_det := jsonb_build_object('antes', to_jsonb(old), 'despues', to_jsonb(new));
  else
    v_reg := (to_jsonb(new)->>'id')::uuid;
    v_det := jsonb_build_object('despues', to_jsonb(new));
  end if;

  insert into public.auditoria (usuario_id, accion, tabla_afectada, registro_id, detalles)
  values (auth.uid(), tg_op, tg_table_name, v_reg, v_det);

  if tg_op = 'DELETE' then return old; end if;
  return new;
end $$;

drop trigger if exists trg_auditar_perfiles    on public.perfiles;
drop trigger if exists trg_auditar_equipos     on public.equipos;
drop trigger if exists trg_auditar_reservas    on public.reservas;
drop trigger if exists trg_auditar_incidencias on public.incidencias;

create trigger trg_auditar_perfiles    after insert or update or delete on public.perfiles    for each row execute function public.fn_auditar();
create trigger trg_auditar_equipos     after insert or update or delete on public.equipos     for each row execute function public.fn_auditar();
create trigger trg_auditar_reservas    after insert or update or delete on public.reservas    for each row execute function public.fn_auditar();
create trigger trg_auditar_incidencias after insert or update or delete on public.incidencias for each row execute function public.fn_auditar();

-- Inmutabilidad: bloquea UPDATE, DELETE y TRUNCATE, incluso para el propietario.
create or replace function public.fn_auditoria_inmutable()
returns trigger language plpgsql as $$
begin
  raise exception 'La tabla auditoria es inmutable (RNF-14): % no permitido.', tg_op using errcode = '42501';
end $$;

drop trigger if exists trg_auditoria_no_mod      on public.auditoria;
drop trigger if exists trg_auditoria_no_truncate on public.auditoria;
create trigger trg_auditoria_no_mod
  before update or delete on public.auditoria
  for each row execute function public.fn_auditoria_inmutable();
create trigger trg_auditoria_no_truncate
  before truncate on public.auditoria
  for each statement execute function public.fn_auditoria_inmutable();

revoke insert, update, delete, truncate on public.auditoria from anon, authenticated;

-- ---------------------------------------------------------------------
-- 6. RPC: DISPONIBILIDAD DE UN EQUIPO (sin exponer datos de otros usuarios)
-- ---------------------------------------------------------------------

create or replace function public.disponibilidad_equipo(p_equipo uuid, p_desde timestamptz, p_hasta timestamptz)
returns table (fecha_inicio timestamptz, fecha_fin timestamptz, estado text, prioridad_uco boolean)
language sql stable security definer set search_path = public as $$
  select r.fecha_inicio, r.fecha_fin, r.estado, r.prioridad_uco
  from public.reservas r
  where r.equipo_id = p_equipo
    and r.estado in ('confirmada','pendiente_prioridad')
    and r.fecha_inicio < p_hasta
    and r.fecha_fin   > p_desde
    and auth.uid() is not null
$$;

revoke execute on function public.disponibilidad_equipo(uuid, timestamptz, timestamptz) from public, anon;
grant  execute on function public.disponibilidad_equipo(uuid, timestamptz, timestamptz) to authenticated;

-- ---------------------------------------------------------------------
-- 7. ROW LEVEL SECURITY (RNF-08)
-- ---------------------------------------------------------------------

alter table public.perfiles       enable row level security;
alter table public.equipos        enable row level security;
alter table public.reservas       enable row level security;
alter table public.incidencias    enable row level security;
alter table public.notificaciones enable row level security;
alter table public.auditoria      enable row level security;

-- perfiles
drop policy if exists perfiles_select        on public.perfiles;
drop policy if exists perfiles_update_propio on public.perfiles;
drop policy if exists perfiles_update_admin  on public.perfiles;
create policy perfiles_select on public.perfiles for select to authenticated
  using (id = auth.uid() or public.rol_actual() in ('administrador','tecnico','responsable_economico'));
create policy perfiles_update_propio on public.perfiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
create policy perfiles_update_admin on public.perfiles for update to authenticated
  using (public.rol_actual() = 'administrador') with check (true);
-- INSERT lo hace el trigger fn_crear_perfil; no hay política de INSERT ni DELETE para clientes.

-- equipos
drop policy if exists equipos_select on public.equipos;
drop policy if exists equipos_insert on public.equipos;
drop policy if exists equipos_update on public.equipos;
drop policy if exists equipos_delete on public.equipos;
create policy equipos_select on public.equipos for select to anon, authenticated
  using (acceso_publico or public.cuenta_aprobada());
create policy equipos_insert on public.equipos for insert to authenticated
  with check (public.rol_actual() = 'administrador');
create policy equipos_update on public.equipos for update to authenticated
  using (public.rol_actual() in ('administrador','tecnico'))
  with check (public.rol_actual() in ('administrador','tecnico'));
create policy equipos_delete on public.equipos for delete to authenticated
  using (public.rol_actual() = 'administrador');

-- reservas
drop policy if exists reservas_select on public.reservas;
drop policy if exists reservas_insert on public.reservas;
drop policy if exists reservas_update on public.reservas;
drop policy if exists reservas_delete on public.reservas;
create policy reservas_select on public.reservas for select to authenticated
  using (usuario_id = auth.uid() or public.rol_actual() in ('administrador','tecnico','responsable_economico'));
create policy reservas_insert on public.reservas for insert to authenticated
  with check (usuario_id = auth.uid() and public.cuenta_aprobada());
create policy reservas_update on public.reservas for update to authenticated
  using (usuario_id = auth.uid() or public.rol_actual() in ('administrador','tecnico'))
  with check (usuario_id = auth.uid() or public.rol_actual() in ('administrador','tecnico'));
create policy reservas_delete on public.reservas for delete to authenticated
  using (public.rol_actual() = 'administrador');

-- incidencias
drop policy if exists incidencias_select on public.incidencias;
drop policy if exists incidencias_insert on public.incidencias;
drop policy if exists incidencias_update on public.incidencias;
drop policy if exists incidencias_delete on public.incidencias;
create policy incidencias_select on public.incidencias for select to authenticated
  using (reportador_id = auth.uid() or public.rol_actual() in ('administrador','tecnico'));
create policy incidencias_insert on public.incidencias for insert to authenticated
  with check (reportador_id = auth.uid() and public.cuenta_aprobada());
create policy incidencias_update on public.incidencias for update to authenticated
  using (public.rol_actual() in ('administrador','tecnico'))
  with check (public.rol_actual() in ('administrador','tecnico'));
create policy incidencias_delete on public.incidencias for delete to authenticated
  using (public.rol_actual() = 'administrador');

-- notificaciones
drop policy if exists notif_select on public.notificaciones;
drop policy if exists notif_insert on public.notificaciones;
drop policy if exists notif_update on public.notificaciones;
drop policy if exists notif_delete on public.notificaciones;
create policy notif_select on public.notificaciones for select to authenticated
  using (usuario_id = auth.uid());
create policy notif_insert on public.notificaciones for insert to authenticated
  with check (public.rol_actual() in ('administrador','tecnico'));
create policy notif_update on public.notificaciones for update to authenticated
  using (usuario_id = auth.uid()) with check (usuario_id = auth.uid());
create policy notif_delete on public.notificaciones for delete to authenticated
  using (usuario_id = auth.uid());

-- auditoria: solo lectura para administradores. Sin políticas de escritura.
drop policy if exists auditoria_select on public.auditoria;
create policy auditoria_select on public.auditoria for select to authenticated
  using (public.rol_actual() = 'administrador');

-- ---------------------------------------------------------------------
-- 8. REALTIME (idempotente)
-- ---------------------------------------------------------------------

do $$
declare t text;
begin
  foreach t in array array['equipos','reservas','incidencias','notificaciones'] loop
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t
    ) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 9. DATOS DE EJEMPLO (opcional; se pueden borrar)
-- ---------------------------------------------------------------------

insert into public.equipos (codigo, nombre, laboratorio, especificaciones, ubicacion_fisica)
values
  ('CICT-001', 'Microscopio electrónico de barrido', 'Microscopía', 'Resolución 1 nm, detector EDS',      'Edificio CICT, planta 0, sala 3'),
  ('CICT-002', 'Espectrómetro de masas ICP-MS',      'Análisis elemental', 'Límite de detección ppt',     'Edificio CICT, planta 1, sala 12'),
  ('CICT-003', 'Cromatógrafo de gases GC-MS',        'Cromatografía', 'Inyector automático de 100 viales','Edificio CICT, planta 1, sala 8')
on conflict (codigo) do nothing;

-- ---------------------------------------------------------------------
-- 10. PRIMER ADMINISTRADOR (ejecutar DESPUÉS de registrarte en la app)
--     Descomenta y cambia el email. Desde el SQL Editor está permitido.
-- ---------------------------------------------------------------------
-- update public.perfiles
--    set rol = 'administrador', estado_cuenta = 'aprobada'
--  where email = 'tu_correo@ejemplo.com';
